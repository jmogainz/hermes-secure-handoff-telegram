"""Bounded structural ENTRY composition. No destination text in public metadata.

Private native bindings and mutation order belong to the controller. This module
only projects generic descriptors and validates model-selected visual groups.
"""
import secrets

ACTIONS = {'discover_components', 'present_composition', 'composition_status', 'cancel_composition'}
TITLES = {'details', 'contact', 'address', 'payment', 'other'}
# Native range/color always have browser defaults. Checkbox needs an explicit
# tri-state UI, so these are not supported by this empty-entry protocol yet.
KINDS = {'text','email','tel','number','password','otp','textarea','select',
         'date','time','datetime-local','month','week','url','search',
         'card_number','card_expiry','cvc'}


def mint(prefix):
    return prefix + secrets.token_urlsafe(24)


def valid_payload(action, payload):
    keys = {
        'discover_components': {'action','session_ref'},
        'present_composition': {'action','snapshot_ref','layout','groups'},
        'composition_status': {'action','component_ref'},
        'cancel_composition': {'action','component_ref'},
    }
    if action not in keys or not isinstance(payload, dict) or set(payload) != keys[action]:
        return False
    if any(not isinstance(payload[k],str) for k in keys[action] - {'groups'}):
        return False
    if any(len(payload[k]) > 80 for k in keys[action] - {'groups'}):
        return False
    if action == 'present_composition':
        groups = payload['groups']
        return (payload['layout'] in {'stack','sections'} and isinstance(groups,list) and 1 <= len(groups) <= 8
                and all(isinstance(g,dict) and set(g)=={'title','refs'} and isinstance(g['title'],str)
                        and g['title'] in TITLES and isinstance(g['refs'],list) and 1 <= len(g['refs']) <= 24
                        and all(isinstance(r,str) and len(r)<=80 for r in g['refs']) for g in groups))
    return True


def project(metadata):
    fields, refs, bindings, options = [], [], {}, {}
    for index, (field_id, meta) in enumerate(metadata.items()):
        if meta['type'] not in KINDS or meta.get('selectionMode') == 'search':
            raise ValueError('unsupported composition control')
        field = {'id':field_id, 'type':meta['type'], 'required':meta['required'],
                 'label':meta['type'].replace('_',' ').replace('-',' ').title() + ' ' + str(index+1)}
        if meta['type'] == 'select':
            options[field_id] = {f'o{i}':o['value'] for i,o in enumerate(meta['options'])}
            field['options'] = [{'value':f'o{i}', 'label':f'Option {i+1}'} for i in range(len(meta['options']))]
        ref=mint('fr_')
        bindings[ref]=field_id
        refs.append({'ref':ref,'kind':meta['type'],'required':meta['required'],'ordinal':index+1})
        fields.append(field)
    return fields, refs, bindings, options


def select_groups(payload, bindings, metadata):
    flat=[r for g in payload['groups'] for r in g['refs']]
    if len(flat)>24 or len(flat)!=len(set(flat)) or any(r not in bindings for r in flat):
        raise ValueError('invalid refs')
    chosen={bindings[r] for r in flat}
    if any(m['required'] and field_id not in chosen for field_id,m in metadata.items()):
        raise ValueError('required field omitted')
    groups=[{'title':g['title'], 'fields':[bindings[r] for r in g['refs']]} for g in payload['groups']]
    return chosen, {'layout':payload['layout'], 'groups':groups}
