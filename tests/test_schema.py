"""Direct contract checks for cases that change the meaning of later analysis."""
from __future__ import annotations

import copy
import json
import unittest
from importlib.resources import files

from structural_safety.schema import validate_structure
from structural_safety.references import validate_references


def known(value):
    return {'state':'known','value':value,'evidence_refs':[]}


def unknown(reason='Not supplied'):
    return {'state':'unknown','reason':reason,'evidence_refs':[]}


def conflict(*values):
    return {'state':'conflict','candidates':[{'value':v,'evidence_refs':[]} for v in values],'evidence_refs':[]}


def fixture():
    return json.loads(files('structural_safety').joinpath('examples/B.json').read_text(encoding='utf-8'))


def diagnostics(doc):
    first=validate_structure(doc)
    return first if first else validate_references(doc)


def extend_operations(doc):
    """One small model expresses every finite operation and supplemental relation."""
    for kind in ['derive','persist_write','persist_read','delegate','policy_update','revoke','stop']:
        doc['context']['operation_definitions'].append({'id':kind,'semantic_kind':kind,'evidence_refs':[]})
        doc['context']['interfaces'].append({'id':'if:'+kind,'node_id':'tool:internal','operation_ids':[kind],
                                             'credential_required':known(True),'evidence_refs':[]})
    def action(name,kind,inputs=None,outputs=None,effects=None):
        return {'id':name,'task_id':'task:demo','workflow_id':'workflow:restricted','context_id':'ctx:restricted',
                'actor_id':'actor:worker','operation_id':kind,'interface_id':'if:'+kind,'purpose_id':'internal_review',
                'effect_time':known('2000-01-01T00:00:55Z'),'inputs':inputs or [],'outputs':outputs or [],
                'success_dependencies':[],'conditions':[],'effects':effects or [],'evidence_refs':[]}
    def port(identifier,obj,node,ctx='not_applicable'):
        return {'port_id':identifier,'object_version_id':obj,'location_node_id':node,'context_id':ctx}
    derived=copy.deepcopy(doc['object_versions'][0])
    derived.update(id='D:v1',logical_id='D',origin_kind='derived',existence='candidate_produced',parents=known(['S:v1']),
                   production={'kind':'candidate_action','action_id':'derive_s','evidence_refs':[]},initial_locations=[])
    doc['object_versions'].append(derived)
    doc['actions'].append(action('derive_s','derive',[port('i','S:v1','actor:worker','ctx:restricted')],
        [port('o','D:v1','actor:worker','ctx:restricted')],[{'id':'e','kind':'produce','input_port_ids':['i'],'output_port_id':'o'}]))
    doc['actions'].append(action('store_d','persist_write',[port('i','D:v1','actor:worker','ctx:restricted')],
        [port('o','D:v1','result:internal')],[{'id':'e','kind':'deliver','input_port_ids':['i'],'output_port_id':'o'}]))
    doc['actions'].append(action('read_d','persist_read',[port('i','D:v1','result:internal')],
        [port('o','D:v1','actor:worker','ctx:restricted')],[{'id':'e','kind':'deliver','input_port_ids':['i'],'output_port_id':'o'}]))
    grant=copy.deepcopy(doc['authorization']['task_grants'][0]);grant['id']='grant:child'
    grant['initially_active']=known(False)
    doc['authorization']['task_grants'].append(grant)
    doc['actions'].append(action('delegate_s','delegate',effects=[{'id':'e','kind':'activate_authorizations','capability_ids':[],
                                                                'task_grant_ids':['grant:child']}]))
    doc['actions'].append(action('policy_s','policy_update',effects=[{'id':'e','kind':'select_policy','control_id':'gate:main',
                                                                   'policy_version_id':'policy:strict','fields':['comment']}]))
    doc['actions'].append(action('revoke_s','revoke',effects=[{'id':'e','kind':'revoke','authorization_ref':{'collection':'task_grants','id':'grant:child'}}]))
    doc['actions'].append(action('stop_s','stop',effects=[{'id':'e','kind':'stop','target':{'collection':'nodes','id':'actor:worker'}}]))
    doc['relations']=[
        {'id':'influence','kind':'semantic_influence','source_object_id':'P:v1','action_id':'publish_s_main','slot':'recipient',
         'context_id':'ctx:restricted','conditions':[],'evidence_refs':[]},
        {'id':'delegation','kind':'delegation','parent_actor_id':'actor:worker','child_actor_id':'actor:worker','action_id':'delegate_s',
         'parent_task_id':'task:demo','child_task_id':'task:demo','parent_grant_ids':[doc['authorization']['task_grants'][0]['id']],
         'child_grant_ids':['grant:child'],'capability_ids':[],'extension_approval_refs':unknown(),'conditions':[],'evidence_refs':[]},
        {'id':'observation','kind':'observation','source':{'collection':'actions','id':'publish_s_main'},'observer_id':'principal:owner',
         'event_kinds':['effect_observed'],'channel':'local log','conditions':[],'evidence_refs':[]},
        {'id':'intervention','kind':'intervention','actor_id':'principal:owner','target':{'collection':'nodes','id':'actor:worker'},
         'operation':'stop','capability_refs':unknown(),'latency':known({'lower':0,'upper':2}),'conditions':[],'evidence_refs':[]},
    ]
    release=copy.deepcopy(doc['authorization']['task_grants'][0]);release.pop('initially_active')
    release['id']='release:test';release['restriction_ids']=known(['restriction:S-v1'])
    release['approval_refs']=known(['approval:owner-release'])
    doc['authorization']['release_exceptions'].append(release)
    doc['obligations']=[{'id':'obligation:test','origin':'supplied','property_id':'P-CONF-01','task_id':'task:demo','applicable':known(True),
        'affected_refs':[{'collection':'actions','id':'publish_s_main'}],'source_refs':known(['S:v1']),'influence_refs':known(['influence']),
        'action_refs':known(['publish_s_main']),'destination_refs':known(['sink:main']),'persistence_refs':known(['result:internal']),
        'control_refs':known(['gate:main']),'responsibility':{'principal':known('principal:owner'),'observation_refs':known(['observation']),
        'intervention_refs':known(['intervention']),'inspectable_basis':unknown(),'verification_reliable':unknown(),'reviewer_capable':unknown(),
        'response':known({'lower':1,'upper':3}),'consequence_window':known({'lower':4,'upper':5}),'trigger':'proposal','evidence_refs':[]},
        'unknown_items':[],'evidence_refs':[]}]
    doc['events']=[{'id':'reported:event','run_id':'external:run','reported_event_kind':'effect_observed','action_id':'publish_s_main',
        'object_ids':['S:v1'],'observer_id':'principal:owner','environment':'deployment','occurred_at':unknown(),
        'recorded_at':'2000-01-01T00:00:59Z','details':'Unverified supplied report','verified':True,'claimed_origin':'tool_run','evidence_refs':[]}]
    return doc


class CompleteContractTests(unittest.TestCase):
    def assert_valid(self,doc):
        self.assertEqual(diagnostics(doc),[])

    def assert_code(self,doc,code):
        self.assertIn(code,[d.code for d in diagnostics(doc)])

    def test_complete_supported_record_families_accept_without_mutation(self):
        doc=extend_operations(fixture());before=copy.deepcopy(doc)
        self.assert_valid(doc)
        self.assertEqual(doc,before)

    def test_unknown_and_conflict_are_valid_without_fake_references(self):
        doc=fixture();doc['nodes'][0]['owner']=unknown()
        doc['authorization']['capabilities'][0]['initially_active']=conflict(True,False)
        doc['object_versions'][0]['parents']=unknown()
        doc['actions'][0]['effect_time']=unknown()
        self.assert_valid(doc)

    def test_cycles_denial_expiry_and_scope_mismatch_are_analysis_inputs(self):
        doc=extend_operations(fixture())
        doc['actions'][0]['success_dependencies']=['read_p']
        doc['actions'][3]['success_dependencies']=['read_s']
        doc['actions'][0]['conditions']=[{'key':'mode','operator':'eq','value':'internal','evidence_refs':[]},
                                        {'key':'mode','operator':'eq','value':'public','evidence_refs':[]}]
        doc['authorization']['task_grants'][0]['validity']=known({'not_before':'1999-01-01T00:00:00Z','expires_at':'1999-01-02T00:00:00Z'})
        doc['authorization']['capabilities']=[]
        doc['object_versions'][-1]['parents']=known(['P:v1'])  # Deliberate source omission for SS004.
        self.assert_valid(doc)

    def test_unknown_fields_in_nested_fact_rejected(self):
        doc=fixture();doc['actions'][0]['effect_time']['verified']=True
        self.assert_code(doc,'unknown_field')

    def test_bad_fact_shapes_rejected(self):
        for bad in [{'state':'known','value':True}, {'state':'unknown','value':True,'reason':'missing','evidence_refs':[]},
                    {'state':'conflict','candidates':[{'value':True,'evidence_refs':[]}],'evidence_refs':[]}]:
            with self.subTest(bad=bad):
                doc=fixture();doc['execution_contexts'][0]['retain_inputs']=bad
                self.assertTrue(diagnostics(doc))

    def test_set_permutations_do_not_create_conflict(self):
        doc=fixture();doc['object_versions'][0]['parents']=conflict(['S:v2','P:v1'],['P:v1','S:v2'])
        self.assert_code(doc,'invalid_fact')

    def test_timestamp_spellings_do_not_create_conflict(self):
        doc=fixture();doc['actions'][0]['effect_time']=conflict('2000-01-01T00:00:10Z','2000-01-01T00:00:10+00:00')
        self.assert_code(doc,'invalid_fact')

    def test_bool_and_number_keep_distinct_condition_values(self):
        doc=fixture();doc['context']['initial_conditions']=[{'key':'choice','value':conflict(True,1)}]
        doc['actions'][0]['conditions']=[{'key':'choice','operator':'in','value':[True,1],'evidence_refs':[]}]
        self.assert_valid(doc)
        doc['context']['initial_conditions'][0]['value']=conflict(1,1.0)
        self.assert_code(doc,'invalid_fact')

    def test_large_finite_integer_does_not_require_float_conversion(self):
        doc=fixture();doc['context']['initial_conditions']=[{'key':'large','value':known(10**400)}]
        self.assert_valid(doc)

    def test_reserved_ids_and_boolean_budget_are_rejected(self):
        for spelling in ['not_applicable','*']:
            with self.subTest(spelling=spelling):
                doc=fixture();doc['nodes'][0]['id']=spelling
                self.assert_code(doc,'reserved_id')
        doc=fixture();doc['limits']['max_states']=True
        self.assert_code(doc,'type_error')

    def test_empty_and_reverse_intervals_rejected_but_expired_valid(self):
        for end in ['2000-01-01T00:00:00Z','1999-01-01T00:00:00Z']:
            doc=fixture();doc['authorization']['capabilities'][0]['validity']['value']['expires_at']=end
            self.assert_code(doc,'invalid_interval')

    def test_wrong_collection_and_node_endpoint_rejected(self):
        doc=fixture();doc['actions'][0]['actor_id']='S:v1'
        self.assert_code(doc,'dangling_reference')
        doc=fixture();doc['actions'][0]['actor_id']='source:private'
        self.assert_code(doc,'endpoint_type')

    def test_duplicate_ids_local_ports_and_version_aliases_rejected(self):
        doc=fixture();doc['nodes'].append(copy.deepcopy(doc['nodes'][0]))
        self.assert_code(doc,'duplicate_id')
        doc=fixture();doc['actions'][0]['outputs'][0]['port_id']=doc['actions'][0]['inputs'][0]['port_id']
        self.assert_code(doc,'duplicate_port')
        doc=fixture();v=copy.deepcopy(doc['object_versions'][0]);v['id']='alias';doc['object_versions'].append(v)
        self.assert_code(doc,'duplicate_version')

    def test_port_mapping_preserves_version_and_local_identity(self):
        doc=fixture();doc['actions'][0]['outputs'][0]['object_version_id']='P:v1'
        self.assert_code(doc,'port_version_mismatch')
        doc=fixture();doc['actions'][0]['effects'][0]['output_port_id']='elsewhere'
        self.assert_code(doc,'dangling_port')

    def test_context_binding_cannot_claim_another_actor_location(self):
        doc=fixture();doc['actions'][0]['outputs'][0]['location_node_id']='principal:owner'
        self.assert_code(doc,'context_location_mismatch')

    def test_candidate_production_cannot_be_initially_held_or_visible(self):
        doc=extend_operations(fixture());doc['object_versions'][-1]['initial_locations']=[{'node_id':'source:private','context_id':'not_applicable'}]
        self.assert_code(doc,'premature_object')
        doc=extend_operations(fixture());doc['execution_contexts'][0]['initial_visible_objects']=known(['D:v1'])
        self.assert_code(doc,'premature_object')

    def test_supported_operation_requires_matching_effect(self):
        doc=fixture();doc['actions'][0]['effects']=[]
        self.assert_code(doc,'missing_effect')
        doc=extend_operations(fixture());doc['actions'][-1]['operation_id']='policy_update';doc['actions'][-1]['interface_id']='if:policy_update'
        self.assert_code(doc,'operation_effect_mismatch')

    def test_unsupported_operation_has_no_invented_supported_effect(self):
        doc=fixture();doc['context']['operation_definitions'].append({'id':'opaque','semantic_kind':'unsupported','unsupported_reason':'Opaque conversion','evidence_refs':[]})
        doc['context']['interfaces'].append({'id':'if:opaque','node_id':'tool:internal','operation_ids':['opaque'],'credential_required':unknown(),'evidence_refs':[]})
        action=copy.deepcopy(doc['actions'][0]);action.update(id='opaque_action',operation_id='opaque',interface_id='if:opaque',effects=[])
        obj=copy.deepcopy(doc['object_versions'][0]);obj.update(id='opaque_output',logical_id='Opaque',origin_kind='unknown',existence='candidate_produced',
            parents=unknown(),parents_complete=unknown(),production={'kind':'candidate_action','action_id':'opaque_action','evidence_refs':[]},initial_locations=[])
        action['outputs'][0]['object_version_id']='opaque_output';doc['object_versions'].append(obj);doc['actions'].append(action)
        self.assert_valid(doc)
        action['effects']=[{'kind':'deliver','id':'fake','input_port_ids':[action['inputs'][0]['port_id']],'output_port_id':action['outputs'][0]['port_id']}]
        self.assert_code(doc,'operation_effect_mismatch')

    def test_policy_selection_is_local_to_control(self):
        doc=extend_operations(fixture());next(a for a in doc['actions'] if a['id']=='policy_s')['effects'][0]['policy_version_id']='undeclared'
        self.assert_code(doc,'dangling_reference')

    def test_relation_and_responsibility_endpoint_kinds(self):
        doc=extend_operations(fixture());doc['relations'][2]['source']={'collection':'object_versions','id':'S:v1'}
        self.assert_code(doc,'endpoint_type')
        doc=extend_operations(fixture());doc['obligations'][0]['responsibility']['observation_refs']=known(['influence'])
        self.assert_code(doc,'endpoint_type')

    def test_completeness_has_one_fact_per_task_and_collection(self):
        doc=fixture();duplicate=copy.deepcopy(doc['context']['completeness'][0])
        duplicate['complete']=known(False);doc['context']['completeness'].append(duplicate)
        self.assert_code(doc,'duplicate_completeness')
        doc=fixture();doc['context']['completeness'][0]['complete']=conflict(True,False)
        self.assert_valid(doc)

    def test_revocation_known_state_and_time_are_consistent(self):
        for state in [{'revoked':True,'at':'not_applicable'},
                      {'revoked':False,'at':'2000-01-01T00:00:01Z'}]:
            doc=fixture();doc['authorization']['capabilities'][0]['revocation']=known(state)
            self.assert_code(doc,'inconsistent_revocation')
        doc=fixture();doc['authorization']['capabilities'][0]['revocation']=unknown('Revocation time unknown')
        self.assert_valid(doc)

    def test_authorization_activation_requires_delegation_mapping(self):
        doc=extend_operations(fixture());doc['relations']=[r for r in doc['relations'] if r['kind']!='delegation']
        doc['obligations']=[]
        self.assert_code(doc,'missing_delegation_mapping')
        doc=extend_operations(fixture());delegate=next(a for a in doc['actions'] if a['id']=='delegate_s')
        delegate['effects'][0]['task_grant_ids'].append('grant:read_s')
        self.assert_code(doc,'missing_delegation_mapping')

    def test_one_immutable_version_has_one_produce_effect(self):
        doc=extend_operations(fixture());producer=next(a for a in doc['actions'] if a['id']=='derive_s')
        output=copy.deepcopy(producer['outputs'][0]);output['port_id']='o2';producer['outputs'].append(output)
        producer['effects'].append({'id':'second','kind':'produce','input_port_ids':['i'],'output_port_id':'o2'})
        self.assert_code(doc,'duplicate_production')

    def test_response_phase_form_accepts_unknown_without_time_inference(self):
        doc=extend_operations(fixture())
        phases={'kind':'sequential_phases','detection':known({'lower':0,'upper':1}),
                'escalation':unknown(),'decision':known({'lower':1,'upper':2}),
                'stop_effect':known({'lower':0,'upper':1}),'sequential':known(False),'nonoverlapping':unknown()}
        doc['obligations'][0]['responsibility']['response']=known(phases)
        self.assert_valid(doc)
        phases['lower']=0;phases['upper']=4
        self.assertTrue(diagnostics(doc))

    def test_explicit_extension_is_valid_but_misspelling_is_not(self):
        doc=fixture();doc['context']['unsupported_items']=[{'id':'opaque:boundary','reason':'External routing omitted','affected_refs':unknown()}]
        self.assert_valid(doc)
        doc['context']['unsupported_item']=doc['context'].pop('unsupported_items')
        self.assert_code(doc,'unknown_field')


if __name__=='__main__':
    unittest.main()
