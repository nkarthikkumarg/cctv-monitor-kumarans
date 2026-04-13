
let flt={zone:'',nvr:'',brand:'',status:''}, q='', selIps=new Set(), selCam=null, uploadFile=null, lastTs=Date.now(), formMode='add';
let notificationRecipients=[];
let userRowsCache=[];

function hc(h){return h>=95?{bg:'#eafaf1',c:'#1e8449'}:h>=80?{bg:'#fef9e7',c:'#d68910'}:{bg:'#fdecea',c:'#c0392b'};}
function bc(b){b=(b||'').toLowerCase();return b==='hikvision'?{bg:'#ebf5fb',c:'#1a5276',l:'HIK'}:b==='dahua'?{bg:'#e8f8f5',c:'#0e6655',l:'DAH'}:{bg:'#fef5e7',c:'#9c640c',l:'PRA'};}
function dc(c){return c.maintenance?'#e67e22':c.online?'#27ae60':'#e74c3c';}
function ts(c){return c.maintenance?'maintenance':c.online?'online':'offline';}
function fmtDateTime(v){
  if(!v)return '—';
  const d=new Date(v);
  if(Number.isNaN(d.getTime()))return v;
  const dd=String(d.getDate()).padStart(2,'0');
  const mm=String(d.getMonth()+1).padStart(2,'0');
  const yyyy=d.getFullYear();
  let hh=d.getHours();
  const min=String(d.getMinutes()).padStart(2,'0');
  const ap=hh>=12?'PM':'AM';
  hh=hh%12||12;
  return `${dd}-${mm}-${yyyy} ${String(hh).padStart(2,'0')}:${min} ${ap}`;
}
function fmtDuration(s){
  if(!s)return '';
  const total=Math.max(0, parseInt(s,10) || 0);
  const d=Math.floor(total/86400);
  const h=Math.floor((total%86400)/3600);
  const m=Math.floor((total%3600)/60);
  const sec=total%60;
  const parts=[];
  if(d)parts.push(`${d}d`);
  if(h)parts.push(`${h}h`);
  if(m)parts.push(`${m}m`);
  if(sec)parts.push(`${sec}s`);
  return parts.join(' ') || '0s';
}
function statusHtml(c){
  if(c.maintenance) return '<span style="color:#e67e22;font-weight:500">Maintenance</span>';
  if(c.online) return '<span style="color:#27ae60;font-weight:500">Online</span>';
  return '<span style="color:#c0392b;font-weight:500">Offline</span>';
}

function sf(k,v,btn){
  flt[k]=v;
  const sel=k==='zone'?'.sidebar .sg:nth-child(1) .sb':k==='nvr'?'.sidebar .sg:nth-child(2) .sb':k==='brand'?'.sidebar .sg:nth-child(3) .sb':'.fbar .chip';
  document.querySelectorAll(sel).forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  syncQuickFilters();
  loadCameras();
}
function fc(){q=document.getElementById('si').value.toLowerCase();loadCameras();}
function setQuickFilter(k,v){
  flt[k]=v;
  const sel=k==='zone'?'.sidebar .sg:nth-child(1) .sb':k==='nvr'?'.sidebar .sg:nth-child(2) .sb':'.sidebar .sg:nth-child(3) .sb';
  document.querySelectorAll(sel).forEach(b=>b.classList.remove('active'));
  const allBtn=document.querySelector(
    k==='zone'?'.sidebar .sg:nth-child(1) .sb':
    k==='nvr'?'.sidebar .sg:nth-child(2) .sb':
    '.sidebar .sg:nth-child(3) .sb'
  );
  let matched=[...document.querySelectorAll(sel)].find(b=>{
    const txt=(b.textContent || '').trim().toLowerCase();
    return v && (txt===v.toLowerCase());
  });
  (matched || allBtn)?.classList.add('active');
  syncQuickFilters();
  loadCameras();
}
function syncQuickFilters(){
  const zone=document.getElementById('zoneFilter');
  const nvr=document.getElementById('nvrFilter');
  const brand=document.getElementById('brandFilter');
  if(zone)zone.value=flt.zone || '';
  if(nvr)nvr.value=flt.nvr || '';
  if(brand)brand.value=flt.brand || '';
}
function clearFilters(){
  flt={zone:'',nvr:'',brand:'',status:''};
  q='';
  document.getElementById('si').value='';
  document.querySelectorAll('.sidebar .sb, .fbar .chip').forEach(b=>b.classList.remove('active'));
  document.querySelector('.sidebar .sg:nth-child(1) .sb')?.classList.add('active');
  document.querySelector('.sidebar .sg:nth-child(2) .sb')?.classList.add('active');
  document.querySelector('.sidebar .sg:nth-child(3) .sb')?.classList.add('active');
  document.querySelector('.fbar .chip')?.classList.add('active');
  syncQuickFilters();
  loadCameras();
}

async function loadStats(){
  const r=await fetch('/api/stats');const s=await r.json();
  document.getElementById('sT').textContent=s.total;
  document.getElementById('sOn').textContent=s.online;
  document.getElementById('sOff').textContent=s.offline;
  document.getElementById('sMt').textContent=s.maintenance;
  const central=s.central||{};
  const consoleInd=document.getElementById('consoleInd');
  const consoleTxt=document.getElementById('consoleTxt');
  if(consoleTxt && consoleInd){
    consoleInd.classList.remove('ok','warn','info');
    if(!central.enabled){
      consoleInd.classList.add('warn');
      consoleTxt.textContent='Console: Disabled';
    }else if(central.healthy){
      consoleInd.classList.add('ok');
      consoleTxt.textContent='Console: Reporting';
    }else{
      consoleInd.classList.add('warn');
      consoleTxt.textContent='Console: Not Reporting';
    }
    const detail = central.last_success_at ? ('Last success: ' + new Date(central.last_success_at).toLocaleString()) : (central.last_error || 'No successful sync yet');
    consoleInd.title = detail;
  }
  const tunnelInd=document.getElementById('tunnelInd');
  const tunnelTxt=document.getElementById('tunnelTxt');
  if(tunnelInd && tunnelTxt){
    tunnelInd.classList.remove('ok','warn','info');
    const apiUrl = (central.api_url || '').trim();
    const publicTunnel = apiUrl && !apiUrl.includes('127.0.0.1') && !apiUrl.includes('localhost');
    if(publicTunnel){
      tunnelInd.classList.add('ok');
      tunnelTxt.textContent='Tunnel: Active';
    }else{
      tunnelInd.classList.add('warn');
      tunnelTxt.textContent='Tunnel: Local Only';
    }
    tunnelInd.title = apiUrl || 'No public tunnel URL configured';
  }
}

async function manualRefresh(){
  const btn=document.getElementById('refreshBtn');
  const txt=document.getElementById('pollTxt');
  btn.disabled=true;
  txt.textContent='Refreshing...';
  try{
    const r=await fetch('/api/refresh',{method:'POST'});
    const d=await r.json();
    if(!r.ok) throw new Error(d.error || 'Refresh failed');
    await loadCameras();
    await refreshMainModal();
    txt.textContent='Live';
  }catch(err){
    txt.textContent='Refresh failed';
    alert(err.message || 'Could not refresh camera status');
  }finally{
    btn.disabled=false;
  }
}

async function loadCameras(){
  const p=new URLSearchParams();
  if(flt.zone)p.set('zone',flt.zone);
  if(flt.nvr)p.set('nvr',flt.nvr);
  if(flt.brand)p.set('brand',flt.brand);
  if(flt.status)p.set('status',flt.status);
  if(q)p.set('q',q);
  const r=await fetch('/api/cameras?'+p);
  const cams=await r.json();
  document.getElementById('ccnt').textContent=cams.length+' cameras';
  document.getElementById('cg').innerHTML=!cams.length
    ? `<div class="empty-state">No cameras match the current filter.</div>`
    : `<table class="cam-table">
        <thead>
          <tr>
            <th style="width:36px"><input type="checkbox" class="row-check" onclick="toggleVisibleSelection(event, ${cams.map(c=>`'${c.ip}'`).join(',')})"></th>
            <th>Status</th>
            <th>Name</th>
            <th>IP Address</th>
            <th>Zone</th>
            <th>NVR</th>
            <th>Brand</th>
            <th>Health</th>
          </tr>
        </thead>
        <tbody>
          ${cams.map(c=>{
            const h=hc(c.health_7d||100),b=bc(c.brand),s=ts(c);
            const sel=selIps.has(c.ip)?'selected':'';
            return `<tr class="${s} ${sel}" data-row-ip="${c.ip}" onclick="openModal('${c.ip}')">
              <td><input type="checkbox" class="row-check" ${selIps.has(c.ip)?'checked':''} onclick="event.stopPropagation();toggleSel('${c.ip}')"></td>
              <td><span class="status-pill ${s}"><span class="dot" style="background:${dc(c)}"></span>${s}</span></td>
              <td><div class="tn">${c.name||'—'}</div><div class="tip">${c.location||''}</div></td>
              <td class="tip">${c.ip}</td>
              <td>${c.zone||'—'}</td>
              <td>${c.nvr_name?`${c.nvr_name} <span style="color:#aaa">Ch.${c.nvr_channel||1}</span>`:'—'}</td>
              <td><span class="bb" style="background:${b.bg};color:${b.c}">${b.l}</span></td>
              <td><span class="hb" style="background:${h.bg};color:${h.c}">${Math.round(c.health_7d||100)}%</span></td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>`;
  loadStats();
  document.getElementById('lastPoll').textContent='Last updated: '+fmtDateTime(new Date());
}

function toggleSel(ip){
  if(selIps.has(ip))selIps.delete(ip);else selIps.add(ip);
  const row=document.querySelector(`[data-row-ip="${ip}"]`);
  row?.classList.toggle('selected', selIps.has(ip));
  const checkbox=row?.querySelector('.row-check');
  if(checkbox)checkbox.checked=selIps.has(ip);
  const bar=document.getElementById('selBar');
  bar.classList.toggle('show',selIps.size>0);
  document.getElementById('selCount').textContent=selIps.size+' cameras selected';
}
function toggleVisibleSelection(event,...ips){
  event.stopPropagation();
  const shouldSelect=event.target.checked;
  ips.forEach(ip=>shouldSelect?selIps.add(ip):selIps.delete(ip));
  document.querySelectorAll('[data-row-ip]').forEach(row=>{
    const ip=row.getAttribute('data-row-ip');
    row.classList.toggle('selected', selIps.has(ip));
    const checkbox=row.querySelector('.row-check');
    if(checkbox)checkbox.checked=selIps.has(ip);
  });
  const bar=document.getElementById('selBar');
  bar.classList.toggle('show',selIps.size>0);
  document.getElementById('selCount').textContent=selIps.size+' cameras selected';
}
function clearSel(){
  selIps.clear();
  document.querySelectorAll('[data-row-ip]').forEach(row=>row.classList.remove('selected'));
  document.querySelectorAll('.row-check').forEach(box=>box.checked=false);
  document.getElementById('selBar').classList.remove('show');
}

function openAddCameraModal(){
  formMode='add';
  document.getElementById('addCameraMsg').textContent='';
  document.getElementById('addCameraForm').reset();
  document.getElementById('cameraFormTitle').textContent='Add Camera Manually';
  document.getElementById('cameraFormSubtitle').textContent='Create or update a single camera without uploading a file.';
  document.getElementById('camChannel').value=1;
  document.getElementById('camUser').value='admin';
  document.getElementById('camNvrIp').value='';
  document.getElementById('camOriginalIp').value='';
  document.getElementById('camIp').readOnly=false;
  document.getElementById('addCameraModal').classList.add('show');
}
function closeAddCameraModal(){
  document.getElementById('addCameraModal').classList.remove('show');
}
function openEditCameraModal(){
  if(!selCam)return;
  formMode='edit';
  document.getElementById('addCameraMsg').textContent='';
  document.getElementById('cameraFormTitle').textContent='Edit Camera';
  document.getElementById('cameraFormSubtitle').textContent='Update this camera and save the changes.';
  document.getElementById('camOriginalIp').value=selCam.ip || '';
  document.getElementById('camIp').value=selCam.ip || '';
  document.getElementById('camIp').readOnly=false;
  document.getElementById('camName').value=selCam.name || '';
  document.getElementById('camLocation').value=selCam.location || '';
  document.getElementById('camZone').value=selCam.zone || '';
  document.getElementById('camNvr').value=selCam.nvr_name || '';
  document.getElementById('camNvrIp').value=selCam.nvr_ip || '';
  document.getElementById('camChannel').value=selCam.nvr_channel || 1;
  document.getElementById('camBrand').value=(selCam.brand || '').toLowerCase();
  document.getElementById('camUser').value=selCam.username || 'admin';
  document.getElementById('camPassword').value=selCam.password || '';
  document.getElementById('camRtsp').value=selCam.rtsp_url || '';
  document.getElementById('camNotes').value=selCam.notes || '';
  document.getElementById('addCameraModal').classList.add('show');
}

async function openSiteSettingsModal(){
  const msg=document.getElementById('siteSettingsMsg');
  msg.style.color='#888';
  msg.textContent='Loading site settings...';
  document.getElementById('siteSettingsModal').classList.add('show');
  const r=await fetch('/api/site-settings');
  const d=await r.json();
  document.getElementById('siteEnabled').checked=!!d.enabled;
  document.getElementById('siteId').value=d.site_id || '';
  document.getElementById('siteName').value=d.site_name || '';
  document.getElementById('siteCampus').value=d.campus || '';
  document.getElementById('siteAddress').value=d.site_address || '';
  document.getElementById('siteContactName').value=d.contact_name || '';
  document.getElementById('siteContactPhone').value=d.contact_phone || '';
  document.getElementById('siteContactEmail').value=d.contact_email || '';
  document.getElementById('siteDashboardUrl').value=d.dashboard_url || '';
  document.getElementById('siteRefreshUrl').value=d.refresh_url || '';
  document.getElementById('siteApiUrl').value=d.api_url || '';
  document.getElementById('siteApiKey').value=d.api_key || '';
  const regBtn=document.getElementById('registerSiteBtn');
  if(regBtn){
    regBtn.textContent=(d.api_key && d.api_key !== 'local-dev-key') ? 'Re-register Site' : 'Register This Site';
  }
  msg.textContent='Edit and save when you are ready.';
}
function closeSiteSettingsModal(){
  document.getElementById('siteSettingsModal').classList.remove('show');
}
async function saveSiteSettings(event){
  event.preventDefault();
  const form=event.target;
  const msg=document.getElementById('siteSettingsMsg');
  const fd=new FormData(form);
  const payload=Object.fromEntries(fd.entries());
  payload.enabled=document.getElementById('siteEnabled').checked;
  msg.style.color='#888';
  msg.textContent='Saving site settings...';
  const r=await fetch('/api/site-settings',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(payload)
  });
  const d=await r.json();
  if(!r.ok){
    msg.style.color='#c0392b';
    msg.textContent=d.error || 'Could not save site settings';
    return;
  }
  document.getElementById('siteNameLabel').textContent=d.settings.site_name || 'Local Site';
  msg.style.color='#27ae60';
  msg.textContent='Saved. Central sync details are updated.';
  setTimeout(()=>closeSiteSettingsModal(), 500);
}
async function registerThisSite(){
  const msg=document.getElementById('siteSettingsMsg');
  const regBtn=document.getElementById('registerSiteBtn');
  regBtn.disabled=true;
  msg.style.color='#888';
  msg.textContent='Registering this site with the central dashboard...';
  const r=await fetch('/api/site-settings/register',{method:'POST'});
  const d=await r.json();
  if(!r.ok){
    regBtn.disabled=false;
    msg.style.color='#c0392b';
    msg.textContent=d.error || 'Could not register this site';
    return;
  }
  document.getElementById('siteApiUrl').value=d.central_api_url || '';
  document.getElementById('siteApiKey').value=d.api_key || '';
  document.getElementById('siteName').value=d.settings.site_name || '';
  document.getElementById('siteCampus').value=d.settings.campus || '';
  document.getElementById('siteId').value=d.settings.site_id || '';
  document.getElementById('siteEnabled').checked=!!d.settings.enabled;
  document.getElementById('siteNameLabel').textContent=d.settings.site_name || 'Local Site';
  regBtn.textContent='Re-register Site';
  regBtn.disabled=false;
  msg.style.color='#27ae60';
  msg.textContent=d.message || 'Site registered with central dashboard and API key saved.';
}

function renderRecipientRows(){
  const wrap=document.getElementById('recipientRows');
  wrap.innerHTML=notificationRecipients.map((r,idx)=>`
    <div style="border:1px solid #e5e7eb;border-radius:10px;padding:10px;background:#fafbfd">
      <div class="form-grid">
        <div class="form-field">
          <label>Name</label>
          <input value="${(r.name||'').replace(/"/g,'&quot;')}" oninput="updateRecipient(${idx},'name',this.value)" placeholder="Security Manager">
        </div>
        <div class="form-field">
          <label>Email</label>
          <input value="${(r.email||'').replace(/"/g,'&quot;')}" oninput="updateRecipient(${idx},'email',this.value)" placeholder="security@example.com">
        </div>
        <div class="form-field">
          <label>WhatsApp</label>
          <input value="${(r.whatsapp||'').replace(/"/g,'&quot;')}" oninput="updateRecipient(${idx},'whatsapp',this.value)" placeholder="whatsapp:+9198xxxxxxx">
        </div>
        <div class="form-field" style="justify-content:flex-end">
          <label>&nbsp;</label>
          <button type="button" class="btn" onclick="removeRecipient(${idx})">Remove</button>
        </div>
        <div class="form-field full" style="flex-direction:row;align-items:center;gap:16px;flex-wrap:wrap">
          <label style="margin:0;display:flex;align-items:center;gap:8px"><input type="checkbox" ${r.email_enabled?'checked':''} onchange="updateRecipient(${idx},'email_enabled',this.checked)"> Email</label>
          <label style="margin:0;display:flex;align-items:center;gap:8px"><input type="checkbox" ${r.whatsapp_enabled?'checked':''} onchange="updateRecipient(${idx},'whatsapp_enabled',this.checked)"> WhatsApp</label>
        </div>
      </div>
    </div>
  `).join('') || '<div style="font-size:12px;color:#888">No recipients added yet.</div>';
}
function addRecipientRow(){
  notificationRecipients.push({name:'',email:'',whatsapp:'',email_enabled:true,whatsapp_enabled:false});
  renderRecipientRows();
}
function removeRecipient(idx){
  notificationRecipients.splice(idx,1);
  renderRecipientRows();
}
function updateRecipient(idx,key,val){
  notificationRecipients[idx][key]=val;
}
async function openNotificationSettingsModal(){
  const msg=document.getElementById('notificationSettingsMsg');
  msg.style.color='#888';
  msg.textContent='Loading notification settings...';
  document.getElementById('notificationSettingsModal').classList.add('show');
  const r=await fetch('/api/notification-settings');
  const d=await r.json();
  document.getElementById('notifPollInterval').value=d.poll_interval ?? 10;
  document.getElementById('notifStatusRetries').value=d.status_retries ?? 1;
  document.getElementById('notifAlertRetries').value=d.alert_ping_retries ?? 6;
  document.getElementById('notifCooldown').value=d.alert_cooldown_minutes ?? 30;
  document.getElementById('notifOfflineToggle').checked=!!d.notify_offline;
  document.getElementById('notifRecoveryToggle').checked=!!d.notify_recovery;
  document.getElementById('notifDailyToggle').checked=!!d.daily_summary_enabled;
  document.getElementById('notifDailyTime').value=d.daily_report_time || '08:00';
  document.getElementById('notifGreeting').value=d.greeting_template || 'Dear {name},';
  document.getElementById('notifEmailEnabled').checked=!!d.email_enabled;
  document.getElementById('notifSmtpHost').value=d.smtp_host || '';
  document.getElementById('notifSmtpPort').value=d.smtp_port ?? 587;
  document.getElementById('notifSmtpTls').checked=!!d.smtp_use_tls;
  document.getElementById('notifSenderEmail').value=d.sender_email || '';
  document.getElementById('notifSenderPassword').value=d.sender_password || '';
  document.getElementById('notifSubjectPrefix').value=d.subject_prefix || '[CAM ALERT]';
  document.getElementById('notifWhatsappEnabled').checked=!!d.whatsapp_enabled;
  document.getElementById('notifSid').value=d.account_sid || '';
  document.getElementById('notifToken').value=d.auth_token || '';
  document.getElementById('notifFromNumber').value=d.from_number || '';
  document.getElementById('offlineTemplate').value=(d.templates||{}).offline || '';
  document.getElementById('recoveryTemplate').value=(d.templates||{}).recovery || '';
  document.getElementById('dailyTemplate').value=(d.templates||{}).daily || '';
  notificationRecipients=(d.recipients || []).map(x=>({...x}));
  renderRecipientRows();
  msg.textContent='Configure timing, channels, and recipients.';
}
function closeNotificationSettingsModal(){
  document.getElementById('notificationSettingsModal').classList.remove('show');
}
async function saveNotificationSettings(event){
  event.preventDefault();
  const msg=document.getElementById('notificationSettingsMsg');
  msg.style.color='#888';
  msg.textContent='Saving notification settings...';
  const payload={
    poll_interval: parseInt(document.getElementById('notifPollInterval').value || '10', 10),
    status_retries: parseInt(document.getElementById('notifStatusRetries').value || '1', 10),
    alert_ping_retries: parseInt(document.getElementById('notifAlertRetries').value || '6', 10),
    alert_cooldown_minutes: parseInt(document.getElementById('notifCooldown').value || '30', 10),
    notify_offline: document.getElementById('notifOfflineToggle').checked,
    notify_recovery: document.getElementById('notifRecoveryToggle').checked,
    daily_summary_enabled: document.getElementById('notifDailyToggle').checked,
    daily_report_time: document.getElementById('notifDailyTime').value,
    greeting_template: document.getElementById('notifGreeting').value,
    email_enabled: document.getElementById('notifEmailEnabled').checked,
    smtp_host: document.getElementById('notifSmtpHost').value,
    smtp_port: parseInt(document.getElementById('notifSmtpPort').value || '587', 10),
    smtp_use_tls: document.getElementById('notifSmtpTls').checked,
    sender_email: document.getElementById('notifSenderEmail').value,
    sender_password: document.getElementById('notifSenderPassword').value,
    subject_prefix: document.getElementById('notifSubjectPrefix').value,
    whatsapp_enabled: document.getElementById('notifWhatsappEnabled').checked,
    account_sid: document.getElementById('notifSid').value,
    auth_token: document.getElementById('notifToken').value,
    from_number: document.getElementById('notifFromNumber').value,
    templates: {
      offline: document.getElementById('offlineTemplate').value,
      recovery: document.getElementById('recoveryTemplate').value,
      daily: document.getElementById('dailyTemplate').value,
    },
    recipients: notificationRecipients,
  };
  const r=await fetch('/api/notification-settings',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(payload)
  });
  const d=await r.json();
  if(!r.ok){
    msg.style.color='#c0392b';
    msg.textContent=d.error || 'Could not save notification settings';
    return;
  }
  msg.style.color='#27ae60';
  msg.textContent='Notification settings saved.';
  setTimeout(()=>closeNotificationSettingsModal(), 600);
}

function renderUserRows(users){
  userRowsCache=users || [];
  const tbody=document.getElementById('userRows');
  tbody.innerHTML=userRowsCache.map(u=>`
    <tr>
      <td><strong>${u.username}</strong></td>
      <td>
        <select onchange="updateUser(${u.id}, {role:this.value})">
          <option value="viewer" ${u.role==='viewer'?'selected':''}>Viewer</option>
          <option value="operator" ${u.role==='operator'?'selected':''}>Operator</option>
          <option value="admin" ${u.role==='admin'?'selected':''}>Admin</option>
        </select>
      </td>
      <td>
        <select onchange="updateUser(${u.id}, {active:this.value==='true'})">
          <option value="true" ${u.active?'selected':''}>Active</option>
          <option value="false" ${!u.active?'selected':''}>Disabled</option>
        </select>
      </td>
      <td><input id="pwd_${u.id}" type="password" placeholder="Leave empty to keep"></td>
      <td><button type="button" class="btn" onclick="saveUserPassword(${u.id})">Update</button></td>
    </tr>
  `).join('') || '<tr><td colspan="5" class="empty-state">No users found.</td></tr>';
}
async function openUserManagementModal(){
  const msg=document.getElementById('userMgmtMsg');
  msg.style.color='#888';
  msg.textContent='Loading users...';
  document.getElementById('userManagementModal').classList.add('show');
  const r=await fetch('/api/users');
  const d=await r.json();
  if(!r.ok){
    msg.style.color='#c0392b';
    msg.textContent=d.error || 'Could not load users';
    return;
  }
  renderUserRows(d);
  msg.textContent='Manage user roles and passwords from here.';
}
function closeUserManagementModal(){
  document.getElementById('userManagementModal').classList.remove('show');
}
async function createUser(){
  const msg=document.getElementById('userMgmtMsg');
  msg.style.color='#888';
  msg.textContent='Creating user...';
  const payload={
    username: document.getElementById('newUsername').value.trim(),
    password: document.getElementById('newUserPassword').value,
    role: document.getElementById('newUserRole').value,
    active: true,
  };
  const r=await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const d=await r.json();
  if(!r.ok){
    msg.style.color='#c0392b';
    msg.textContent=d.error || 'Could not create user';
    return;
  }
  document.getElementById('newUsername').value='';
  document.getElementById('newUserPassword').value='';
  document.getElementById('newUserRole').value='viewer';
  msg.style.color='#27ae60';
  msg.textContent=`User ${d.user.username} created.`;
  const rows=await fetch('/api/users');
  renderUserRows(await rows.json());
}
async function updateUser(id, changes){
  const msg=document.getElementById('userMgmtMsg');
  const r=await fetch(`/api/users/${id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(changes)});
  const d=await r.json();
  if(!r.ok){
    msg.style.color='#c0392b';
    msg.textContent=d.error || 'Could not update user';
    return;
  }
  msg.style.color='#27ae60';
  msg.textContent=`Updated ${d.user.username}.`;
}
async function saveUserPassword(id){
  const input=document.getElementById(`pwd_${id}`);
  const password=input.value;
  if(!password)return;
  await updateUser(id, {password});
  input.value='';
}

async function submitCameraForm(event){
  event.preventDefault();
  const form=event.target;
  const msg=document.getElementById('addCameraMsg');
  const payload=Object.fromEntries(new FormData(form).entries());
  payload.nvr_channel=parseInt(payload.nvr_channel || '1', 10);
  msg.style.color='#888';
  msg.textContent='Saving camera...';
  const r=await fetch('/api/camera',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(payload)
  });
  const d=await r.json();
  if(!r.ok){
    msg.style.color='#c0392b';
    msg.textContent=d.error || 'Could not save camera';
    return;
  }
  closeAddCameraModal();
  if(selCam && selCam.ip === payload.ip){
    selCam = {...selCam, ...payload};
  }
  await loadCameras();
  if(formMode==='edit'){
    await openModal(payload.ip);
  } else {
    window.location.reload();
  }
}

function copyTextValue(value){
  if(!value) return;
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(value);
  }
}
function shouldUseProxyPlayer(playerUrl){
  if(!playerUrl) return false;
  const host=window.location.hostname;
  const port=window.location.port;
  return !(host==='127.0.0.1' && port==='5001');
}
async function toggleFullscreen(elementId){
  const el=document.getElementById(elementId);
  if(!el) return;
  const img=el.querySelector('img');
  if(document.fullscreenElement){
    await document.exitFullscreen();
    if(img){
      img.style.width='100%';
      img.style.height='auto';
      img.style.maxHeight='65vh';
      img.style.objectFit='contain';
    }
    return;
  }
  if(el.requestFullscreen){
    await el.requestFullscreen();
    if(img){
      img.style.width='100vw';
      img.style.height='100vh';
      img.style.maxHeight='100vh';
      img.style.objectFit='contain';
    }
  }
}
let mainPreviewTimer=null;
function stopMainPreview(){
  if(mainPreviewTimer){
    window.clearInterval(mainPreviewTimer);
    mainPreviewTimer=null;
  }
}
function startMainPreview(snapshotUrl){
  stopMainPreview();
  if(!snapshotUrl) return;
  const img=document.getElementById('mainPreviewImg');
  if(!img) return;
  const refresh=()=>{ img.src=`${snapshotUrl}${snapshotUrl.includes('?')?'&':'?'}t=${Date.now()}`; };
  refresh();
  mainPreviewTimer=window.setInterval(refresh, 500);
}

function renderMainModal(c){
  selCam=c;
  document.getElementById('mNm').textContent=c.name;
  document.getElementById('mNmDot').style.background=dc(c);
  document.getElementById('mSb').textContent=`${c.ip}  •  ${c.location||''}, ${c.zone||''}  •  ${c.nvr_name||''} Ch.${c.nvr_channel||1}`;
  const pb=document.getElementById('pvb');
  pb.style.height='auto';
  pb.style.minHeight='0';
  pb.style.padding='0';
  pb.style.background='transparent';
  pb.style.border='none';
  const browserStream=(c.stream_urls||{}).browser || (c.stream_urls||{}).mjpeg || '';
  const snapshotStream=(c.stream_urls||{}).snapshot || '';
  const playerStream=(c.stream_urls||{}).player || '';
  if(c.online&&!c.maintenance&&c.stream_urls){
    if(shouldUseProxyPlayer(playerStream)){
      stopMainPreview();
      pb.innerHTML=`<div id="mainPreviewFrame" style="width:100%;border:1px solid #cbd5e1;border-radius:12px;overflow:hidden;background:#fff">
        <iframe src="${playerStream}" allow="autoplay; fullscreen; picture-in-picture" allowfullscreen style="display:block;width:100%;height:65vh;border:0;background:#000"></iframe>
      </div>`;
    }else{
      pb.innerHTML=`<div id="mainPreviewFrame" ondblclick="toggleFullscreen('mainPreviewFrame')" style="width:100%;border:1px solid #cbd5e1;border-radius:12px;overflow:hidden;cursor:zoom-in;background:#fff">
        <img id="mainPreviewImg" style="width:100%;height:auto;max-height:65vh;object-fit:contain;background:#fff;display:block">
      </div>`;
      const img=document.getElementById('mainPreviewImg');
      if(browserStream){
        stopMainPreview();
        img.onerror=()=>{
          img.onerror=null;
          if(snapshotStream){
            startMainPreview(snapshotStream);
          }else{
            img.parentElement.innerHTML=`<div style="color:#aaa;font-size:12px;padding:24px;text-align:center;border:1px solid #e5e7eb;border-radius:12px;background:#fff">Live preview unavailable</div>`;
          }
        };
        img.src=browserStream;
      }else if(snapshotStream){
        img.onerror=()=>{
          img.onerror=null;
          img.parentElement.innerHTML=`<div style="color:#aaa;font-size:12px;padding:24px;text-align:center;border:1px solid #e5e7eb;border-radius:12px;background:#fff">Live preview unavailable</div>`;
        };
        startMainPreview(snapshotStream);
      }else{
        img.parentElement.innerHTML=`<div style="color:#aaa;font-size:12px;padding:24px;text-align:center;border:1px solid #e5e7eb;border-radius:12px;background:#fff">Live preview unavailable</div>`;
      }
    }
  } else if(!c.online){
    stopMainPreview();
    pb.innerHTML=`<div style="text-align:center;color:#c0392b;padding:28px;border:1px solid #e5e7eb;border-radius:12px;background:#fff"><div style="font-size:32px;margin-bottom:8px">🔴</div><div style="font-weight:600">Camera Offline</div><div style="font-size:11px;color:#aaa;margin-top:6px">Offline since ${fmtDateTime(c.offline_since)}</div></div>`;
  } else {
    stopMainPreview();
    pb.innerHTML=`<div style="text-align:center;color:#e67e22;padding:28px;border:1px solid #e5e7eb;border-radius:12px;background:#fff"><div style="font-size:32px;margin-bottom:8px">🟡</div><div style="font-weight:600">Maintenance Mode</div></div>`;
  }
  const h=hc(c.health_7d||100);
  document.getElementById('mRws').innerHTML=[
    ['Zone',c.zone||'—'],['Location',c.location||'—'],['Brand',(c.brand||'').charAt(0).toUpperCase()+(c.brand||'').slice(1)],
    ['NVR / Channel',(c.nvr_name||'')+'  /  Ch.'+(c.nvr_channel||1)],
    ['NVR IP',c.nvr_ip||'—'],
    ['7-day Health',`<span style="background:${h.bg};color:${h.c};padding:2px 7px;border-radius:4px;font-weight:600">${Math.round(c.health_7d||100)}%</span>`],
    ['Status',statusHtml(c)],
    ['Notes',c.notes||'—'],
  ].map(([l,v])=>`<div class="irow"><span class="ilbl">${l}</span><span>${v}</span></div>`).join('');
  
  document.getElementById('mRws').innerHTML += `<div class="irow"><span class="ilbl">RTSP URL</span><span style="font-family:monospace;font-size:10px;color:#3498db;word-break:break-all;overflow-wrap:anywhere">${(c.stream_urls||{}).rtsp||'—'}</span></div>`;
  
  document.getElementById('mtog').className='tog'+(c.maintenance?' on':'');
  const ev=(c.history||[]).slice(0,5).map(h=>`<div style="font-size:11px;padding:4px 0;border-bottom:1px solid #f5f5f5;color:${h.event==='offline'?'#c0392b':h.event==='online'?'#27ae60':'#888'}">${h.event==='offline'?'🔴':'🟢'} ${h.event.charAt(0).toUpperCase()+h.event.slice(1)} — ${fmtDateTime(h.ts)}${h.event==='online'&&h.duration_s?` <span style="color:#888">(${fmtDuration(h.duration_s)} downtime)</span>`:''}</div>`).join('');
  document.getElementById('mEv').innerHTML=ev||'<div style="color:#aaa;font-size:11px">No events recorded yet</div>';
  document.getElementById('ov').classList.add('show');
}
async function openModal(ip){
  const r=await fetch('/api/camera/'+ip);
  const c=await r.json();
  renderMainModal(c);
}
async function refreshMainModal(){
  if(!selCam || !document.getElementById('ov').classList.contains('show')) return;
  const r=await fetch('/api/camera/'+selCam.ip);
  const c=await r.json();
  renderMainModal(c);
}

function co(){stopMainPreview();document.getElementById('ov').classList.remove('show');selCam=null;}

async function deleteSelectedCamera(){
  if(!selCam) return;
  const label=selCam.name || selCam.ip;
  if(!confirm(`Delete ${label}?`)) return;
  const typed=prompt(`Type DELETE to confirm removing ${label}`);
  if(typed !== 'DELETE') return;
  const r=await fetch('/api/camera/'+encodeURIComponent(selCam.ip), {method:'DELETE'});
  const d=await r.json();
  if(!r.ok){
    alert(d.error || 'Could not delete camera');
    return;
  }
  co();
  clearSel();
  loadCameras();
}

function applyMaintenanceStateLocally(ip, maintenance){
  if(selCam && selCam.ip===ip){
    selCam.maintenance=maintenance;
    document.getElementById('mtog').className='tog'+(maintenance?' on':'');
    const statusEl=document.getElementById('mSt');
    if(statusEl)statusEl.innerHTML=statusHtml(selCam);
    const dot=document.getElementById('mNmDot');
    if(dot)dot.style.background=dc(selCam);
  }
}

async function tm(){
  if(!selCam)return;
  const toggle=document.getElementById('mtog');
  if(toggle?.dataset.busy==='1')return;
  const newState=!selCam.maintenance;
  const prevState=selCam.maintenance;
  if(toggle)toggle.dataset.busy='1';
  applyMaintenanceStateLocally(selCam.ip, newState);
  try{
    const r=await fetch('/api/camera/'+selCam.ip+'/maintenance',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({state:newState})});
    const d=await r.json();
    if(!r.ok) throw new Error(d.error || 'Could not update maintenance mode');
    loadCameras();
    refreshMainModal();
  }catch(err){
    applyMaintenanceStateLocally(selCam.ip, prevState);
    alert(err.message || 'Could not update maintenance mode');
  }finally{
    if(toggle)toggle.dataset.busy='0';
  }
}

async function bulkMaint(state){
  if(!selIps.size)return;
  const ips=[...selIps];
  if(selCam && ips.includes(selCam.ip)){
    applyMaintenanceStateLocally(selCam.ip, state);
  }
  await fetch('/api/bulk/maintenance',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ips,state})});
  clearSel();loadCameras();refreshMainModal();
}
async function showBulkZone(){
  const z=prompt('Enter zone name:');if(!z)return;
  await fetch('/api/bulk/zone',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ips:[...selIps],zone:z})});
  clearSel();loadCameras();
}
async function showBulkNvr(){
  const n=prompt('Enter NVR name:');if(!n)return;
  await fetch('/api/bulk/nvr',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ips:[...selIps],nvr:n})});
  clearSel();loadCameras();
}

async function deleteSelectedCameras(){
  if(!selIps.size) return;
  const count=selIps.size;
  const selected=[...selIps].map(ip=>{
    const row=document.querySelector(`[data-row-ip="${ip}"]`);
    const name=row?.querySelector('.tn')?.textContent?.trim();
    return name && name !== '—' ? `${name} (${ip})` : ip;
  });
  const preview=selected.slice(0,5).join('\n');
  const extra=count>5 ? `\n...and ${count-5} more` : '';
  if(!confirm(`Delete ${count} selected camera${count===1?'':'s'}?\n\n${preview}${extra}`)) return;
  const typed=prompt(`Type DELETE to confirm removing:\n\n${preview}${extra}`);
  if(typed !== 'DELETE') return;
  const r=await fetch('/api/bulk/delete',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ips:[...selIps]})
  });
  const d=await r.json();
  if(!r.ok){
    alert(d.error || 'Could not delete selected cameras');
    return;
  }
  if(selCam && selIps.has(selCam.ip)){
    co();
  }
  clearSel();
  loadCameras();
}

async function previewUpload(input){
  const file=input.files[0];if(!file)return;
  uploadFile=file;
  const fd=new FormData();fd.append('file',file);
  const r=await fetch('/api/bulk/preview',{method:'POST',body:fd});
  const d=await r.json();
  if(!r.ok){
    document.getElementById('diffArea').innerHTML=`<div style="padding:12px;border:1px solid #fecaca;background:#fff1f2;color:#b91c1c;border-radius:12px;font-size:12px">${d.error||'Preview failed'}</div>`;
    document.getElementById('uploadActions').style.display='none';
    return;
  }
  const rows=d.preview||[];
  const summary=d.summary||{};
  const errors=d.errors||[];
  const warnings=d.warnings||[];
  const errorHtml=errors.length?`<div style="margin-bottom:10px;padding:12px;border:1px solid #fecaca;background:#fff1f2;color:#991b1b;border-radius:12px;font-size:12px;line-height:1.55">
    <div style="font-weight:700;margin-bottom:6px">Errors to fix before import</div>
    <ul style="margin-left:18px">${errors.slice(0,8).map(x=>`<li>Row ${x.row}: ${x.text}</li>`).join('')}${errors.length>8?`<li>...and ${errors.length-8} more</li>`:''}</ul>
  </div>`:'';
  const warningHtml=warnings.length?`<div style="margin-bottom:10px;padding:12px;border:1px solid #fed7aa;background:#fff7ed;color:#9a3412;border-radius:12px;font-size:12px;line-height:1.55">
    <div style="font-weight:700;margin-bottom:6px">Warnings to review</div>
    <ul style="margin-left:18px">${warnings.slice(0,8).map(x=>`<li>Row ${x.row}: ${x.text}</li>`).join('')}${warnings.length>8?`<li>...and ${warnings.length-8} more</li>`:''}</ul>
  </div>`:'';
  const html=`<div style="font-size:12px;margin-bottom:8px"><strong>${summary.total||rows.length}</strong> cameras found — <span style="color:#27ae60">${summary.new||0} new</span>, <span style="color:#e67e22">${summary.updates||0} updates</span>, <span style="color:#b91c1c">${summary.errors||0} errors</span>, <span style="color:#b45309">${summary.warnings||0} warnings</span></div>
  ${errorHtml}
  ${warningHtml}
  <div style="max-height:240px;overflow-y:auto"><table class="diff-table"><thead><tr><th>Row</th><th>IP</th><th>Name</th><th>NVR</th><th>NVR IP</th><th>Brand</th><th>Action</th><th>Checks</th></tr></thead><tbody>
  ${rows.slice(0,30).map(r=>`<tr>
    <td>${r.row}</td>
    <td style="font-family:monospace">${r.ip}</td>
    <td>${r.name||'—'}</td>
    <td>${r.nvr_name||'—'}</td>
    <td style="font-family:monospace">${r.nvr_ip||'—'}</td>
    <td>${r.brand||'—'}</td>
    <td style="color:${r.action==='add'?'#27ae60':'#e67e22'};font-weight:600">${r.action}</td>
    <td>${(r.messages||[]).length? (r.messages||[]).map(m=>`<div style="color:${m.level==='error'?'#b91c1c':'#9a3412'}">${m.level}: ${m.text}</div>`).join('') : '<span style="color:#15803d">ok</span>'}</td>
  </tr>`).join('')}
  ${rows.length>30?`<tr><td colspan="8" style="color:#aaa;text-align:center">...and ${rows.length-30} more</td></tr>`:''}
  </tbody></table></div>`;
  document.getElementById('diffArea').innerHTML=html;
  document.getElementById('uploadActions').style.display=d.blocking?'none':'block';
}

async function confirmUpload(){
  if(!uploadFile)return;
  const fd=new FormData();fd.append('file',uploadFile);
  const r=await fetch('/api/bulk/import',{method:'POST',body:fd});
  const d=await r.json();
  if(!r.ok){
    alert(d.error || 'Import failed');
    return;
  }
  document.getElementById('uploadModal').classList.remove('show');
  alert(`Import complete: ${d.added} added, ${d.updated} updated${(d.warnings||[]).length?`, ${(d.warnings||[]).length} warnings reviewed`:''}`);
  loadCameras();
}

setInterval(async()=>{await loadCameras();await refreshMainModal();}, 30000);
loadCameras();



// Handled server-side at /audit
