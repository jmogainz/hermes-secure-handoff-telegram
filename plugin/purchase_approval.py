"""Purchase engine with public-summary publication disabled for generic DOM.

Only a code-reviewed runtime adapter with independent public-catalog provenance
may supply the narrow typed contract. No adapters ship here. Semantic DOM rows
are private equality/binding checks, never public text sources. Validation does
not establish provenance or merchant truth. Unsupported transactions stay human
owned; this is an intentional compatibility reduction, not any-site readiness.
"""
import secrets
from datetime import date


def validate_source_contract(value):
    """Validate semantics, NOT provenance. For reviewed runtime adapters only.

    Adapters must source public catalog identity independently of account/form
    text and attest the complete transaction, including all legal obligations,
    price components and fixed future renewal prices. Unknown/variable terms,
    currencies other than USD, trials, discounts and supplemental obligations
    are unsupported. Never call this on scraped prose or a model payload and
    treat successful validation as establishing privacy or completeness.
    """
    def fields(obj, names):
        if type(obj) is not dict or set(obj) != set(names.split()):
            raise ValueError('unsupported source contract')

    def money(price):
        fields(price, 'subtotal tax fees total')
        if any(type(n) is not int or not 0 <= n <= 9999999999 for n in price.values()):
            raise ValueError('unresolved price')
        if price['total'] != price['subtotal'] + price['tax'] + price['fees']:
            raise ValueError('contradictory price')
        return f"{price['total'] // 100}.{price['total'] % 100:02d}"

    fields(value, 'version item merchant currency price refund recurrence')
    if type(value['version']) is not int or value['version'] != 1 or value['currency'] != 'USD':
        raise ValueError('unsupported source contract')
    for key in ('item', 'merchant'):
        text = value[key]
        if type(text) is not str or not 1 <= len(text) <= 160 or text.strip() != text or not all(32 <= ord(c) <= 126 for c in text):
            raise ValueError('invalid catalog label')
    if value['refund'] != 'non_refundable':
        raise ValueError('unsupported terms')
    total = money(value['price'])
    recurrence = value['recurrence']
    if type(recurrence) is not dict:
        raise ValueError('incomplete recurrence')
    item = value['item']
    terms = 'Non-refundable. Total includes all tax and fees. No other charges or obligations.'
    if recurrence.get('kind') == 'one_time':
        fields(recurrence, 'kind')
        renewal = 'No renewal. One-time purchase.'
    else:
        fields(recurrence, 'kind first_start first_end renewal_start cadence price')
        if recurrence['kind'] != 'recurring' or recurrence['cadence'] not in ('daily', 'weekly', 'monthly', 'annually'):
            raise ValueError('unsupported recurrence')
        for key in ('first_start', 'first_end', 'renewal_start'):
            text = recurrence[key]
            if type(text) is not str:
                raise ValueError('incomplete recurrence')
            try:
                parsed = date.fromisoformat(text)
            except ValueError:
                raise ValueError('invalid term date') from None
            if parsed.isoformat() != text:
                raise ValueError('invalid term date')
        if not recurrence['first_start'] < recurrence['first_end'] or recurrence['first_end'] != recurrence['renewal_start']:
            raise ValueError('contradictory renewal transition')
        renewal_total = money(recurrence['price'])
        item += f"; first term [{recurrence['first_start']}, {recurrence['first_end']}) at 00:00 UTC"
        renewal = f"Renews {recurrence['cadence']} at USD {renewal_total} including tax; cancel before renewal."
        terms += f" First renewal starts {recurrence['renewal_start']} at 00:00 UTC. Renewal price is fixed and includes all tax and fees; cancel before each renewal."
    return {'item': item, 'merchant': value['merchant'], 'currency': 'USD',
            'totalIncludingTax': total, 'renewal': renewal, 'terms': terms}

# This closure is private in the disposable/live browser context. It is never
# installed on window or returned through a model-facing tool.
PIN_PURCHASE = r"""({base,scope,action,deadline,expected}) => {
    const doc=document, url=location.href, nativeClick=HTMLElement.prototype.click;
    const visible = e => {
        if (!e || !e.isConnected || e.ownerDocument !== doc || !e.getClientRects().length) return false;
        for (let n=e;n;n=n.parentElement) {
            const s=getComputedStyle(n);
            if (n.inert || n.getAttribute('aria-hidden')==='true' || s.display==='none' ||
                s.visibility!=='visible' || Number(s.opacity)<=0 || s.pointerEvents==='none') return false;
        }
        return true;
    };
    const keys=['item','merchant','currency','totalIncludingTax','renewal','terms'];
    // Exact semantic aliases, not price/merchant inference from arbitrary text.
    const aliases=[['Item','Items','Product','Products'],['Merchant','Seller'],['Currency'],
        ['Total including tax','Total including tax and fees','Total including taxes and fees'],
        ['Renewal','Billing frequency'],['Terms','Purchase terms']];
    const names=new Set(['Transaction summary','Order summary','Purchase summary','Checkout summary']);
    const heading=e=>[...e.children].find(n=>/^(H[1-6]|CAPTION)$/.test(n.tagName));
    const title=e=>e.getAttribute('aria-label') || (heading(e) && visible(heading(e)) ? heading(e).innerText.trim() : '');
    const roots=()=>[...scope.querySelectorAll('dl,table,section,[role="region"],[role="group"]')]
        .filter(e=>visible(e) && names.has(title(e)));
    const initial=roots();
    if(initial.length!==1) throw Error('summary unavailable');
    const root=initial[0];
    // Candidates are private semantic node pairs, NOT selectors or model text.
    // Re-discovery checks identity only; it never adopts a replacement source.
    const candidates=()=>{
        let container=root, children=[...root.children].filter(n=>n!==heading(root));
        if(children.length===1 && /^(DL|TABLE|UL|OL)$/.test(children[0].tagName)) {
            container=children[0];
            children=[...container.children];
        }
        if(container.tagName==='DL') {
            children=[...container.children];
            if(children.length===6 && children.every(e=>e.tagName==='DIV' && e.children.length===2)) {
                children=children.flatMap(e=>[...e.children]);
            }
            if(children.length!==12) throw Error('ambiguous summary');
            return keys.map((key,i)=>{
                const label=children[i*2], value=children[i*2+1];
                if(label.tagName!=='DT' || value.tagName!=='DD') throw Error('missing summary term');
                return {label,value};
            });
        }
        if(container.tagName==='TABLE') {
            if(container.rows.length!==6) throw Error('ambiguous summary');
            return [...container.rows].map(row=>{
                const cells=[...row.cells];
                if(cells.length!==2 || cells[0].tagName!=='TH' || !['','row'].includes(cells[0].scope) || cells[1].tagName!=='TD') throw Error('ambiguous summary');
                return {label:cells[0],value:cells[1]};
            });
        }
        if(children.length!==6) throw Error('ambiguous summary');
        return children.map(row=>{
            const cells=[...row.children];
            if(!/^(DIV|P|LI)$/.test(row.tagName) || cells.length!==2 ||
                cells.some(e=>! /^(SPAN|STRONG|B)$/.test(e.tagName))) throw Error('ambiguous summary');
            return {label:cells[0],value:cells[1]};
        });
    };
    const refs=candidates();
    const safeSources=()=>{
        // Reject controls BEFORE reading any display text. Native values are
        // consulted later only privately, for echo/change detection.
        const elements=[root,...root.querySelectorAll('*')];
        if(elements.length>128) throw Error('summary too complex');
        const texts=refs.flatMap(ref=>[ref.label,ref.value]);
        const h=heading(root);
        if(h) texts.push(h);
        for(const e of elements) {
            if(!/^(DL|DT|DD|TABLE|CAPTION|TBODY|THEAD|TFOOT|TR|TH|TD|SECTION|DIV|P|UL|OL|LI|SPAN|STRONG|B|BR|H[1-6])$/.test(e.tagName) ||
                !visible(e) || e.hasAttribute('contenteditable') || e.shadowRoot) throw Error('unsafe summary');
            const style=getComputedStyle(e);
            if(style.textDecorationLine.includes('line-through')) throw Error('obsolete summary');
            for(const pseudo of ['::before','::after']) {
                if(!['none','normal','""'].includes(getComputedStyle(e,pseudo).content)) throw Error('generated summary');
            }
            if(/^(H[1-6]|CAPTION)$/.test(e.tagName) && e!==h) throw Error('ambiguous heading');
            // Every non-whitespace text node must belong to a bound source.
            // Unknown adjacent text/financial rows are not silently dropped.
            for(const n of e.childNodes) {
                if(n.nodeType===Node.TEXT_NODE && n.textContent.trim() &&
                    !texts.some(source=>source.contains(n))) throw Error('unbound summary text');
            }
        }
    };
    const read=()=>{
        const live=roots();
        if(live.length!==1 || live[0]!==root || !visible(root)) throw Error('summary changed');
        safeSources();
        const current=candidates();
        if(current.some((ref,i)=>ref.label!==refs[i].label || ref.value!==refs[i].value)) throw Error('summary source changed');
        const summary={};
        for(const {label,value} of refs) {
            if(!visible(label) || !visible(value)) throw Error('missing summary term');
            const index=aliases.findIndex(group=>group.includes(label.innerText.trim()));
            if(index<0 || Object.hasOwn(summary,keys[index])) throw Error('ambiguous summary');
            const text=value.innerText.trim();
            if(!text || text.length>512 || /[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/.test(text)) throw Error('invalid summary');
            summary[keys[index]]=text;
        }
        // Prose is never a source of public authority. Compare privately against
        // the reviewed adapter's generated contract; return only that contract.
        if(!expected || keys.some(key=>summary[key]!==expected[key])) throw Error('unreviewed summary');
        return {...expected};
    };
    base.check();
    const summary=read(), encoded=JSON.stringify(summary);
    const controls=[...doc.querySelectorAll('input,textarea,select')];
    // Includes hidden transaction IDs, shipping choices and payment method state.
    // Never serialize these values out of this browser closure.
    const values=controls.map(e=>[e.value,e.checked,e.selectedIndex]);
    let changed=false, revoked=false;
    const observer=new MutationObserver(()=>{changed=true;});
    // Observe the full bound checkout scope: a new fee/qualification outside
    // the selected summary still invalidates approval, without exporting text.
    observer.observe(scope,{subtree:true,childList:true,characterData:true,attributes:true});
    // Value properties need not cause DOM mutations. Retain an event epoch as
    // well as final private equality, so user A -> B -> A edits cannot revive
    // approval. Capture also covers non-bubbling events on original controls.
    const fieldChanged=event=>{
        if(scope.contains(event.target) || controls.includes(event.target)) changed=true;
    };
    doc.addEventListener('input',fieldChanged,true);
    doc.addEventListener('change',fieldChanged,true);
    const stopObserving=()=>{
        observer.disconnect();
        doc.removeEventListener('input',fieldChanged,true);
        doc.removeEventListener('change',fieldChanged,true);
    };
    const lease={consumed:false, deadline, summary:Object.freeze(summary)};
    Object.defineProperty(lease,'revoked',{
        get:()=>revoked,
        set:value=>{if(value){revoked=true;stopObserving();values.length=0;base.revoked=true;}}
    });
    lease.check=()=>{
        if(observer.takeRecords().length) changed=true;
        if(changed) throw Error('summary epoch changed');
        if(lease.revoked || lease.consumed || Date.now()>=lease.deadline || document!==doc || location.href!==url) throw Error('stale purchase');
        base.check();
        if(JSON.stringify(read())!==encoded) throw Error('transaction changed');
        const live=[...doc.querySelectorAll('input,textarea,select')];
        if(live.length!==controls.length || live.some((e,i)=>e!==controls[i] ||
            e.value!==values[i][0] || e.checked!==values[i][1] || e.selectedIndex!==values[i][2])) throw Error('billing changed');
        return true;
    };
    lease.commit=({deadline})=>{
        lease.deadline=Math.min(lease.deadline,deadline);
        lease.check();
        if(!visible(action) || action.matches(':disabled')) throw Error('unusable action');
        const r=action.getBoundingClientRect(), hit=doc.elementFromPoint(r.left+r.width/2,r.top+r.height/2);
        if(!hit || !(hit===action || action.contains(hit))) throw Error('covered action');
        lease.check();
        lease.consumed=true; // irrevocable BEFORE invoking destination code
        nativeClick.call(action);
        return true;
    };
    return lease;
}"""

# Intentionally empty: only code-reviewed runtime adapters may be installed here.
# Never populate from DOM attributes, tool/model payloads, or user form values.
_REVIEWED_SOURCES = {}


class PublicFactSourceUnavailable(ValueError):
    """Missing provenance infrastructure; never include destination text."""


async def pin_purchase(session):
    from urllib.parse import urlsplit
    url = urlsplit(session.page.url)
    source = _REVIEWED_SOURCES.get(f'{url.scheme}://{url.netloc}')
    if source is None:
        raise PublicFactSourceUnavailable('reviewed purchase source required')
    summary = validate_source_contract(await source(session))
    return await session.page.evaluate_handle(PIN_PURCHASE, {
        'expected': summary,
        'base': session.commit_guard, 'scope': session.scope,
        'action': session.refs['submit'], 'deadline': session.request['expiresAt'],
    })


def approval_request(make_request, origin, summary, deadline, demo=False):
    request, key = make_request(origin, [], demo, mode='payment_confirmation',
                                stage='purchase_approval', action_label='Complete purchase')
    request['mode'] = 'purchase_approval'
    request['transaction'] = {'id': 'tx_' + secrets.token_urlsafe(24), 'summary': summary}
    request['expiresAt'] = min(request['expiresAt'], deadline)
    return request, key
