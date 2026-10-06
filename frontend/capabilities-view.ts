import type {EngineCapabilities,FeatureId} from '../backend/engine/capabilities.js';

const tabFeatures:Record<string,FeatureId>={strings:'strings',refs:'references',xref:'references',symbols:'symbols',imports:'symbols',exports:'symbols',flow:'flow',calls:'flow',variables:'variables',types:'types',bookmarks:'bookmarks',edit:'programEditing',notes:'annotations',bytesearch:'byteSearch',instructions:'textSearch','code-search':'textSearch'};
/** Pure policy shared by tab rendering and its tests. Runtime loss never hides saved results. */
export function tabCapability(tab:string,capabilities:EngineCapabilities):{enabled:boolean;reason:string} {
    if(tab==='edit')return capabilities.actions.edit;
    const feature=tabFeatures[tab];
    if(!feature)return {enabled:true,reason:''};
    const value=capabilities.features[feature];
    return {enabled:value.status!=='unsupported',reason:value.detail};
}
export function renderCapabilities(container:HTMLElement,c:EngineCapabilities){
    const heading=document.createElement('h3');heading.textContent=c.name;container.append(heading);
    const info=document.createElement('p');info.textContent=c.inputs+(c.runtimeAvailable?'':' '+c.runtimeReason);container.append(info);
    const table=document.createElement('table');
    const head=document.createElement('tr');for(const label of ['Capacidad','Cobertura','Alcance']){const th=document.createElement('th');th.textContent=label;head.append(th);}const thead=document.createElement('thead');thead.append(head);table.append(thead);
    const body=document.createElement('tbody');
    const labels={supported:'Disponible',partial:'Parcial',unsupported:'No implementada'};
    for(const feature of Object.values(c.features)){const row=document.createElement('tr');for(const value of [feature.label,labels[feature.status],feature.detail]){const cell=document.createElement('td');cell.textContent=value;row.append(cell);}body.append(row);}
    table.append(body);container.append(table);
}
