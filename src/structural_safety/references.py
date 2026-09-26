"""Typed identity and endpoint validation; no reachability or authorization inference."""
from __future__ import annotations

from typing import Any, Iterator

from .model import Diagnostic
from .schema import INPUT_CONTRACT, _check, _resolve, pointer

_ACTORS = {'principal', 'executor', 'service'}
_AUTHORIZATION = {'capabilities', 'task_grants', 'approval_rights', 'release_exceptions'}


def _fact_values(value: dict) -> list:
    if value['state'] == 'known':
        return [value['value']]
    if value['state'] == 'conflict':
        return [candidate['value'] for candidate in value['candidates']]
    return []


def _walk(value: Any, spec: dict, path: str = '') -> Iterator[tuple[Any, dict, str]]:
    if spec['type'] == 'definition':
        if spec['name'] == 'policy_target':
            yield value, {'type': 'policy_target'}, path
            return
        if spec['name'] == 'typed_ref':
            yield value, {'type':'typed_ref'}, path
            return
        yield from _walk(value, INPUT_CONTRACT['definitions'][spec['name']], path)
        return
    kind=spec['type']
    if kind=='ref':
        yield value,spec,path
    elif kind=='object':
        for key,child in spec['fields'].items():
            if key in value:
                yield from _walk(value[key],child,pointer(path,key))
    elif kind=='array':
        for i,item in enumerate(value):
            yield from _walk(item,spec['items'],pointer(path,i))
    elif kind=='fact':
        for i,ref in enumerate(value['evidence_refs']):
            yield ref,{'type':'ref','collection':'evidence'},pointer(pointer(path,'evidence_refs'),i)
        if value['state']=='known':
            yield from _walk(value['value'],spec['value'],pointer(path,'value'))
        elif value['state']=='conflict':
            for i,candidate in enumerate(value['candidates']):
                base=pointer(pointer(path,'candidates'),i)
                yield from _walk(candidate['value'],spec['value'],pointer(base,'value'))
                for j,ref in enumerate(candidate['evidence_refs']):
                    yield ref,{'type':'ref','collection':'evidence'},pointer(pointer(base,'evidence_refs'),j)
    elif kind=='union':
        for child in spec['variants']:
            errors=[]
            _check(value,child,path,errors)
            if not errors:
                yield from _walk(value,child,path)
                break


def validate_references(document: dict) -> list[Diagnostic]:
    """Check a structurally valid document's references and immutable identities.

    This deliberately accepts unreachable actions, conflicting facts, denied grants,
    cyclic success dependencies, and incorrect source declarations for later analysis.
    """
    errors: list[Diagnostic] = []

    def issue(code: str, path: str, message: str) -> None:
        errors.append(Diagnostic(code=code,path=path,message=message))

    collections={name:(document[name],'/'+name) for name in (
        'nodes','execution_contexts','object_versions','actions','relations','restrictions','controls','obligations','evidence')}
    collections['events']=(document.get('events',[]),'/events')
    for name,field in [('tasks','tasks'),('workflows','workflows'),('interfaces','interfaces'),
                       ('operations','operation_definitions'),('purposes','purposes'),('properties','properties')]:
        collections[name]=(document['context'][field],'/context/'+field)
    for name in sorted(_AUTHORIZATION):
        collections[name]=(document['authorization'][name],'/authorization/'+name)
    indexes={}
    paths={}
    for collection,(records,base) in collections.items():
        index={}
        for i,record in enumerate(records):
            at=pointer(base,i)
            identifier=record['id']
            if identifier in index:
                issue('duplicate_id',pointer(at,'id'),'ID is duplicated within its typed collection.')
            else:
                index[identifier]=record
                paths[(collection,identifier)]=at
            if identifier in ('*','not_applicable'):
                issue('reserved_id',pointer(at,'id'),'This identifier is reserved and cannot identify a record.')
        indexes[collection]=index
    extra_seen=set()
    for i,record in enumerate(document['context']['unsupported_items']):
        if record['id'] in extra_seen:
            issue('duplicate_id',f'/context/unsupported_items/{i}/id','Unsupported item ID is duplicated.')
        extra_seen.add(record['id'])
    completeness_keys=set()
    for i,entry in enumerate(document['context']['completeness']):
        key=(entry['task_id'],entry['collection'])
        if key in completeness_keys:
            issue('duplicate_completeness',f'/context/completeness/{i}','Completeness must have one Fact per task and collection; use an explicit conflict.')
        completeness_keys.add(key)
    initial_keys=set()
    for i,binding in enumerate(document['context']['initial_conditions']):
        if binding['key'] in initial_keys:
            issue('duplicate_id',f'/context/initial_conditions/{i}/key','Initial condition key is duplicated; use a Fact conflict.')
        initial_keys.add(binding['key'])

    for value,spec,path in _walk(document,INPUT_CONTRACT['root']):
        if spec['type']=='policy_target':
            control=indexes['controls'].get(value['control_id'])
            if control is None or not any(p['id']==value['policy_version_id'] for p in control['policy_versions']):
                issue('dangling_reference',path,'Policy target must name a declared version of that exact control.')
            continue
        if spec['type']=='typed_ref':
            collection=value['collection'];identifier=value['id']
            destination=pointer(path,'id')
        else:
            collection=spec['collection'];identifier=value;destination=path
            if identifier=='not_applicable' and spec.get('not_applicable'):
                continue
        target=indexes[collection].get(identifier)
        if target is None:
            issue('dangling_reference',destination,'Reference does not identify a member of the required collection.')
        elif spec.get('kinds') and target.get('kind') not in spec['kinds']:
            issue('endpoint_type',destination,'Referenced node kind is invalid for this endpoint.')

    nodes=indexes['nodes'];contexts=indexes['execution_contexts'];objects=indexes['object_versions']
    actions=indexes['actions'];workflows=indexes['workflows'];operations=indexes['operations']
    controls=indexes['controls'];interfaces=indexes['interfaces']

    def location(node_id: str, context_id: str, path: str) -> None:
        if context_id=='not_applicable':
            return
        ctx=contexts.get(context_id)
        if ctx is not None and ctx['actor_id']!=node_id:
            issue('context_location_mismatch',path,'Context-bearing location must be held by its context actor.')

    for i,ctx in enumerate(document['execution_contexts']):
        workflow=workflows.get(ctx['workflow_id'])
        if workflow and workflow['task_id']!=ctx['task_id']:
            issue('context_identity_mismatch',f'/execution_contexts/{i}/workflow_id','Workflow belongs to a different task.')
        for visible in _fact_values(ctx['initial_visible_objects']):
            for obj_id in visible:
                obj=objects.get(obj_id)
                if obj and obj['existence']=='candidate_produced':
                    issue('premature_object',f'/execution_contexts/{i}/initial_visible_objects','Candidate-produced objects cannot be initially visible.')

    versions=set()
    for i,obj in enumerate(document['object_versions']):
        base=f'/object_versions/{i}'
        identity=(obj['logical_id'],obj['version'])
        if identity in versions:
            issue('duplicate_version',base,'Logical object and version pair identifies more than one object record.')
        versions.add(identity)
        for j,loc in enumerate(obj['initial_locations']):
            location(loc['node_id'],loc['context_id'],f'{base}/initial_locations/{j}')
        production=obj['production']
        if obj['existence']=='candidate_produced':
            if obj['initial_locations']:
                issue('premature_object',base+'/initial_locations','Candidate-produced objects cannot have initial locations.')
            if production['kind']!='candidate_action':
                issue('production_mismatch',base+'/production','Candidate-produced objects require a candidate producer.')
            else:
                producer=actions.get(production.get('action_id'))
                if producer:
                    ports={p['port_id']:p for p in producer['outputs']}
                    produced=[e for e in producer['effects'] if e['kind']=='produce' and
                              ports.get(e['output_port_id'],{}).get('object_version_id')==obj['id']]
                    producer_kind=operations.get(producer['operation_id'],{}).get('semantic_kind')
                    opaque_output=producer_kind=='unsupported' and any(p['object_version_id']==obj['id'] for p in producer['outputs'])
                    if not produced and not opaque_output:
                        issue('production_mismatch',base+'/production','Producer has no matching output definition for this version.')
        elif production['kind']=='candidate_action':
            issue('production_mismatch',base+'/production','An initial version cannot also be a current candidate production.')

    policy_indexes={}
    for i,control in enumerate(document['controls']):
        policies={}
        for j,policy in enumerate(control['policy_versions']):
            if policy['id'] in policies:
                issue('duplicate_id',f'/controls/{i}/policy_versions/{j}/id','Policy version ID is duplicated within its control.')
            policies[policy['id']]=policy
        policy_indexes[control['id']]=policies
        for initial in _fact_values(control['initial_policy']):
            if initial not in policies:
                issue('dangling_reference',f'/controls/{i}/initial_policy','Initial policy is not one of this control\'s declared versions.')

    allowed_effects={'read':{'deliver'},'transfer':{'deliver'},'persist_write':{'deliver'},
                     'persist_read':{'deliver'},'derive':{'produce'},'delegate':{'activate_authorizations'},
                     'policy_update':{'select_policy'},'revoke':{'revoke'},'stop':{'stop'},'unsupported':set()}
    for i,action in enumerate(document['actions']):
        base=f'/actions/{i}'
        ctx=contexts.get(action['context_id'])
        if ctx and (ctx['actor_id'],ctx['task_id'],ctx['workflow_id'])!=(action['actor_id'],action['task_id'],action['workflow_id']):
            issue('action_context_mismatch',base+'/context_id','Action and execution context must have the same actor, task, and workflow.')
        wf=workflows.get(action['workflow_id'])
        if wf and wf['task_id']!=action['task_id']:
            issue('action_context_mismatch',base+'/workflow_id','Action workflow belongs to a different task.')
        interface=interfaces.get(action['interface_id'])
        if interface and action['operation_id'] not in interface['operation_ids']:
            issue('interface_operation_mismatch',base+'/operation_id','Operation is not declared on this interface.')
        all_ports={};inputs={};outputs={}
        for direction,target in [('inputs',inputs),('outputs',outputs)]:
            for j,port in enumerate(action[direction]):
                pp=f'{base}/{direction}/{j}'
                if port['port_id'] in all_ports:
                    issue('duplicate_port',pp+'/port_id','Port ID must be unique within its action.')
                all_ports[port['port_id']]=port;target[port['port_id']]=port
                location(port['location_node_id'],port['context_id'],pp)
        semantic=operations.get(action['operation_id'],{}).get('semantic_kind')
        if semantic and semantic!='unsupported' and not action['effects']:
            issue('missing_effect',base+'/effects','Supported operations require an explicit finite effect.')
        effect_ids=set();output_uses={};produced_versions=set()
        for j,effect in enumerate(action['effects']):
            ep=f'{base}/effects/{j}';kind=effect['kind']
            if effect['id'] in effect_ids:
                issue('duplicate_id',ep+'/id','Effect ID must be unique within its action.')
            effect_ids.add(effect['id'])
            if semantic and kind not in allowed_effects[semantic]:
                issue('operation_effect_mismatch',ep+'/kind','Effect is incompatible with the declared operation semantics.')
            if kind in ('deliver','produce'):
                for k,port_id in enumerate(effect['input_port_ids']):
                    if port_id not in inputs:
                        issue('dangling_port',f'{ep}/input_port_ids/{k}','Effect input must name this action\'s input port.')
                port_id=effect['output_port_id'];out=outputs.get(port_id)
                if out is None:
                    issue('dangling_port',ep+'/output_port_id','Effect output must name this action\'s output port.')
                else:
                    output_uses[port_id]=output_uses.get(port_id,0)+1
                    if kind=='deliver':
                        if len(effect['input_port_ids'])!=1:
                            issue('port_mapping_mismatch',ep+'/input_port_ids','An unchanged transfer has exactly one input port.')
                        for ref in effect['input_port_ids']:
                            if ref in inputs and inputs[ref]['object_version_id']!=out['object_version_id']:
                                issue('port_version_mismatch',ep,'An unchanged transfer must preserve its input object version.')
                    else:
                        if out['object_version_id'] in produced_versions:
                            issue('duplicate_production',ep,'An immutable object version has exactly one produce effect.')
                        produced_versions.add(out['object_version_id'])
                        obj=objects.get(out['object_version_id'])
                        if obj and (obj['existence']!='candidate_produced' or obj['production'].get('action_id')!=action['id']):
                            issue('production_mismatch',ep,'A produce effect must bind its unique candidate output version.')
                    if semantic=='persist_write' and nodes.get(out['location_node_id'],{}).get('kind')!='store':
                        issue('endpoint_type',ep+'/output_port_id','Persistence writes must target a store node.')
                if semantic=='persist_read':
                    for ref in effect['input_port_ids']:
                        if ref in inputs and nodes.get(inputs[ref]['location_node_id'],{}).get('kind')!='store':
                            issue('endpoint_type',ep+'/input_port_ids','Persistence reads must read a store node.')
            elif kind=='activate_authorizations':
                mappings=[r for r in document['relations'] if r['kind']=='delegation' and r['action_id']==action['id']]
                mapped_grants={ref for r in mappings for ref in r['child_grant_ids']}
                mapped_caps={ref for r in mappings for ref in r['capability_ids']}
                if not mappings or not set(effect['task_grant_ids']).issubset(mapped_grants) or not set(effect['capability_ids']).issubset(mapped_caps):
                    issue('missing_delegation_mapping',ep,'Activated records require a linked delegation relation with parent and child identities.')
            elif kind=='select_policy':
                if effect['control_id'] in policy_indexes and effect['policy_version_id'] not in policy_indexes[effect['control_id']]:
                    issue('dangling_reference',ep+'/policy_version_id','Selected policy must belong to the named control.')
            elif kind=='revoke' and effect['authorization_ref']['collection'] not in _AUTHORIZATION:
                issue('endpoint_type',ep+'/authorization_ref','Revocation target must be an authorization record.')
            elif kind=='stop':
                _target(effect['target'],ep+'/target',indexes,issue)
        if semantic!='unsupported':
            for port_id in outputs:
                if output_uses.get(port_id,0)!=1:
                    issue('port_mapping_mismatch',base+'/outputs','Every output port must be bound by exactly one data effect.')

    for i,relation in enumerate(document['relations']):
        base=f'/relations/{i}';kind=relation['kind']
        if kind=='semantic_influence':
            action=actions.get(relation['action_id'])
            if action and action['context_id']!=relation['context_id']:
                issue('relation_context_mismatch',base+'/context_id','Influence context must be the influenced action context.')
        elif kind=='delegation':
            action=actions.get(relation['action_id'])
            if action:
                semantic=operations.get(action['operation_id'],{}).get('semantic_kind')
                if semantic!='delegate':
                    issue('relation_action_mismatch',base+'/action_id','Delegation relation must identify a delegate action.')
                if action['actor_id']!=relation['parent_actor_id'] or action['task_id']!=relation['parent_task_id']:
                    issue('relation_action_mismatch',base+'/action_id','Delegation action must identify its parent actor and task.')
                activated_grants={v for e in action['effects'] if e['kind']=='activate_authorizations' for v in e['task_grant_ids']}
                activated_caps={v for e in action['effects'] if e['kind']=='activate_authorizations' for v in e['capability_ids']}
                if not set(relation['child_grant_ids']).issubset(activated_grants) or not set(relation['capability_ids']).issubset(activated_caps):
                    issue('relation_effect_mismatch',base,'Delegated records must be explicitly activated by the linked action.')
        elif kind=='observation' and relation['source']['collection'] not in ('nodes','actions'):
            issue('endpoint_type',base+'/source','Observation source must be a node or action.')
        elif kind=='intervention':
            if relation['operation']=='revoke':
                if relation['target']['collection'] not in _AUTHORIZATION:
                    issue('endpoint_type',base+'/target','Revoke interventions target authorization records.')
            else:
                _target(relation['target'],base+'/target',indexes,issue)
    for i,entry in enumerate(document['context']['stopped_targets']):
        _target(entry['target'],f'/context/stopped_targets/{i}/target',indexes,issue)
    for i,obligation in enumerate(document['obligations']):
        for field,required in [('observation_refs','observation'),('intervention_refs','intervention')]:
            for refs in _fact_values(obligation['responsibility'][field]):
                for ref in refs:
                    relation=indexes['relations'].get(ref)
                    if relation and relation['kind']!=required:
                        issue('endpoint_type',f'/obligations/{i}/responsibility/{field}','Responsibility reference names the wrong relation kind.')
        for refs in _fact_values(obligation['influence_refs']):
            for ref in refs:
                relation=indexes['relations'].get(ref)
                if relation and relation['kind']!='semantic_influence':
                    issue('endpoint_type',f'/obligations/{i}/influence_refs','Influence reference must name semantic_influence.')
    return errors


def _target(ref: dict, path: str, indexes: dict, issue) -> None:
    collection=ref['collection']
    if collection not in ('actions','interfaces','nodes'):
        issue('endpoint_type',path,'Stop/pause target must be an action, interface, or actor.')
    elif collection=='nodes':
        target=indexes['nodes'].get(ref['id'])
        if target and target['kind'] not in _ACTORS:
            issue('endpoint_type',path,'Node stop/pause targets must be actors; use an interface for a tool endpoint.')
