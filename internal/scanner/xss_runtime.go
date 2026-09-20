package scanner

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	cdppage "github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// runtimeDOMHit is emitted by the short-lived browser instrumentation installed
// around one XSS canary navigation. A hit is routing evidence (the canary reached
// a dangerous browser sink), not vulnerability proof. Promotion still requires
// the normal random-nonce JavaScript execution proof.
type runtimeDOMHit struct {
	Sink    string `json:"sink"`
	Preview string `json:"preview"`
	Stack   string `json:"stack"`
}

const runtimeDOMResultKey = "__reconnerXSSRuntime"

const xssProofResultKey = "__reconnerXSSProof"

// xssProofObserverScript creates a nonce-scoped execution channel before any
// application JavaScript runs. document.title remains the normal top-level
// proof, while postMessage lets a payload executing in a cross-origin iframe
// prove execution without trying to read top.document (which browsers block).
func xssProofObserverScript(nonce string) string {
	nonceJSON, _ := json.Marshal(nonce)
	return `(()=>{try{const nonce=` + string(nonceJSON) + `;Object.defineProperty(window,'` + xssProofResultKey + `',{value:'',writable:true,configurable:true});addEventListener('message',e=>{try{const d=e.data;if(d&&d.__reconnerXSSProof===nonce)window.` + xssProofResultKey + `=nonce}catch(_){}})}catch(_){}})();`
}

// installXSSProofObserver registers the observer for the upcoming navigation and
// every child frame, then removes it after the single proof attempt.
func installXSSProofObserver(ctx, tab context.Context, nonce string) (remove func()) {
	if strings.TrimSpace(nonce) == "" {
		return func() {}
	}
	var id cdppage.ScriptIdentifier
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(actionCtx context.Context) error {
		var addErr error
		id, addErr = cdppage.AddScriptToEvaluateOnNewDocument(xssProofObserverScript(nonce)).Do(actionCtx)
		return addErr
	}))
	if err != nil || id == "" {
		return func() {}
	}
	return func() {
		cleanupCtx, cancel := context.WithTimeout(tab, 2*time.Second)
		defer cancel()
		_ = chromedp.Run(cleanupCtx, chromedp.ActionFunc(func(actionCtx context.Context) error {
			return cdppage.RemoveScriptToEvaluateOnNewDocument(id).Do(actionCtx)
		}))
	}
}

// runtimeDOMInstrumentationScript hooks native DOM/code sinks before application
// JavaScript starts. The wrappers never suppress or rewrite an operation; they
// only record values containing this navigation's random canary. This catches
// transient flows that outerHTML cannot see (for example innerHTML is assigned
// and immediately cleared during hydration).
func runtimeDOMInstrumentationScript(marker string) string {
	markerJSON, _ := json.Marshal(marker)
	return `(()=>{try{
const marker=` + string(markerJSON) + `;
const state={marker,hits:[]};
Object.defineProperty(window,'` + runtimeDOMResultKey + `',{value:state,configurable:true});
const text=v=>{try{if(typeof v==='string')return v;if(v==null)return '';return JSON.stringify(v)}catch(_){try{return String(v)}catch(_){return ''}}};
const record=(sink,value)=>{const raw=text(value);if(!raw.includes(marker)||state.hits.length>=32)return;let stack='';try{stack=String(new Error().stack||'').split('\n').slice(2,7).join('\n')}catch(_){};state.hits.push({sink,preview:raw.slice(0,240),stack:stack.slice(0,800)})};
const method=(obj,name,sink,indices)=>{try{const original=obj&&obj[name];if(typeof original!=='function')return;Object.defineProperty(obj,name,{configurable:true,writable:true,value:function(...args){for(const i of indices)record(sink,args[i]);return Reflect.apply(original,this,args)}})}catch(_){}};
const setter=(obj,name,sink)=>{try{const d=Object.getOwnPropertyDescriptor(obj,name);if(!d||!d.configurable||typeof d.set!=='function')return;Object.defineProperty(obj,name,{configurable:true,enumerable:d.enumerable,get:d.get,set:function(v){record(sink,v);return Reflect.apply(d.set,this,[v])}})}catch(_){}};
setter(Element.prototype,'innerHTML','Element.innerHTML');
setter(Element.prototype,'outerHTML','Element.outerHTML');
if(window.ShadowRoot)setter(ShadowRoot.prototype,'innerHTML','ShadowRoot.innerHTML');
if(window.HTMLIFrameElement)setter(HTMLIFrameElement.prototype,'srcdoc','HTMLIFrameElement.srcdoc');
if(window.HTMLScriptElement)setter(HTMLScriptElement.prototype,'src','HTMLScriptElement.src');
if(window.HTMLIFrameElement)setter(HTMLIFrameElement.prototype,'src','HTMLIFrameElement.src');
method(Element.prototype,'insertAdjacentHTML','Element.insertAdjacentHTML',[1]);
method(Element.prototype,'setAttribute','Element.setAttribute',[1]);
method(Element.prototype,'setHTMLUnsafe','Element.setHTMLUnsafe',[0]);
if(window.ShadowRoot)method(ShadowRoot.prototype,'setHTMLUnsafe','ShadowRoot.setHTMLUnsafe',[0]);
method(Document.prototype,'write','Document.write',[0]);
method(Document.prototype,'writeln','Document.writeln',[0]);
if(window.Document)method(Document,'parseHTMLUnsafe','Document.parseHTMLUnsafe',[0]);
if(window.Range)method(Range.prototype,'createContextualFragment','Range.createContextualFragment',[0]);
if(window.DOMParser)method(DOMParser.prototype,'parseFromString','DOMParser.parseFromString',[0]);
method(window,'setTimeout','window.setTimeout',[0]);
method(window,'setInterval','window.setInterval',[0]);
}catch(_){}})();`
}

// installRuntimeDOMInstrumentation registers the hook for documents created by
// the upcoming navigation. remove must be called after the navigation so marker-
// specific scripts do not accumulate on the process-wide reusable browser tab.
func installRuntimeDOMInstrumentation(ctx, tab context.Context, marker string) (remove func()) {
	if strings.TrimSpace(marker) == "" {
		return func() {}
	}
	var id cdppage.ScriptIdentifier
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(actionCtx context.Context) error {
		var addErr error
		id, addErr = cdppage.AddScriptToEvaluateOnNewDocument(runtimeDOMInstrumentationScript(marker)).Do(actionCtx)
		return addErr
	}))
	if err != nil || id == "" {
		return func() {}
	}
	return func() {
		cleanupCtx, cancel := context.WithTimeout(tab, 2*time.Second)
		defer cancel()
		_ = chromedp.Run(cleanupCtx, chromedp.ActionFunc(func(actionCtx context.Context) error {
			return cdppage.RemoveScriptToEvaluateOnNewDocument(id).Do(actionCtx)
		}))
	}
}

func readRuntimeDOMHits(ctx context.Context) []runtimeDOMHit {
	var hits []runtimeDOMHit
	expr := `(()=>{const s=window.` + runtimeDOMResultKey + `;return s&&Array.isArray(s.hits)?s.hits:[]})()`
	_ = chromedp.Run(ctx, chromedp.Evaluate(expr, &hits))
	return hits
}

func runtimeDOMHitSummary(hits []runtimeDOMHit) string {
	if len(hits) == 0 {
		return ""
	}
	seen := map[string]bool{}
	parts := make([]string, 0, len(hits))
	for _, hit := range hits {
		sink := strings.TrimSpace(hit.Sink)
		if sink == "" || seen[sink] {
			continue
		}
		seen[sink] = true
		parts = append(parts, sink)
		if len(parts) == 6 {
			break
		}
	}
	return strings.Join(parts, " -> ")
}
