<h1>Azure Honeypot Project (SIEM with Microsoft Sentinel)</h1>

<h2>Overview</h2>
<p>
This project demonstrates how to set up a honeypot in Microsoft Azure and monitor attack logs using Microsoft Sentinel and Log Analytics Workspace. It includes log enrichment using IP geolocation and visualizing attacks on a world map using a Sentinel Workbook.
  <img width="1433" height="714" alt="Screenshot (17)" src="https://github.com/user-attachments/assets/be1f3ecd-70d4-4c21-a2da-13247fd103ec" />

</p>

<hr/>

<h2>Part 1: Setup Azure Subscription</h2>
<ul>
  <li>Create a free Azure subscription: <a href="https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account">Azure Free Account</a></li>
  <li>Login to Azure Portal: <a href="https://portal.azure.com">portal.azure.com</a></li>
</ul>

<h2>Part 2: Create the Honeypot (Azure VM)</h2>
<ol>
  <li>Create a Windows 10 Virtual Machine from the Azure portal.</li>
  <li>Allow all inbound traffic from the Network Security Group (NSG).</li>
  <li>Disable the Windows Firewall on the VM (Start > wf.msc > Properties > Off).</li>
  <img width="1391" height="825" alt="Screenshot (18)" src="https://github.com/user-attachments/assets/d1ceaa08-1932-47c8-82ce-06a282a91d75" />

</ol>

<h2>Part 3: Generate and Inspect Logs</h2>
<ol>
  <li>Attempt 3 failed logins as "employee" or another username.</li>
  <li>Login to the VM and open Event Viewer → Security logs.</li>
  <li>Search for Event ID <b>4625</b> to see failed login attempts.</li>
  <img width="1567" height="920" alt="Screenshot (19)" src="https://github.com/user-attachments/assets/8cc7c8ca-365b-4056-9d61-3d9a20388e63" />

</ol>

<h2>Part 4: Connect to Sentinel & Query Logs</h2>
<ol>
  <li>Create a Log Analytics Workspace (LAW).</li>
  <img width="1403" height="800" alt="Screenshot (20)" src="https://github.com/user-attachments/assets/0c1c5890-193c-4477-abdb-57864b33df17" />

  <li>Create a Microsoft Sentinel instance and connect it to the LAW.</li>
  <li>Use the "Windows Security Events via AMA" data connector.</li>
  <img width="1373" height="787" alt="Screenshot (21)" src="https://github.com/user-attachments/assets/fecb637a-fee1-4eb8-be3c-55dd4f4745e0" />

  <li>Query for failed login logs using KQL:</li>

  <img width="1364" height="819" alt="Screenshot (22)" src="https://github.com/user-attachments/assets/df202985-11be-4b03-a695-ea99443e9e86" />

</ol>


<pre>
SecurityEvent
| where EventId == 4625
</pre>

<h2>Part 5: Log Enrichment with Location Data</h2>
<ol>
  <li>Download and upload <code>geoip-summarized.csv</code> as a Watchlist in Microsoft Sentinel.</li>
  <li>Name/Alias: <b>geoip</b>, Source: Local File, Search Key: <b>network</b>.</li>
  <li>Use the following query to enrich logs with geolocation:</li>
</ol>

<pre>
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
  | where IpAddress == "<attacker IP address>"
  | where EventID == 4625
  | order by TimeGenerated desc
  | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
    <img width="1374" height="843" alt="Screenshot (24)" src="https://github.com/user-attachments/assets/f9160af3-8e9b-4c4b-81a6-f376eec946a7" />

</pre>

<h2>Part 6: Create a World Map of Attacks (Sentinel Workbook)</h2>
<ol>
  <li>Create a new Workbook in Sentinel.</li>
  <li>Delete default elements and add a Query element.</li>
  <li>Go to "Advanced Editor" and paste your map JSON (e.g., <code>map.json</code> file).</li>
  <li>Customize the map visualization to show IP locations from log data.</li>
  <img width="1364" height="811" alt="Screenshot (25)" src="https://github.com/user-attachments/assets/d2840b93-4a87-4f04-85de-bf32c06ec8a4" />

</ol>

<h2>Technologies Used</h2>
<ul>
  <li><b>Microsoft Azure</b></li>
  <li><b>Microsoft Sentinel</b></li>
  <li><b>Log Analytics Workspace</b></li>
  <li><b>KQL (Kusto Query Language)</b></li>
  <li><b>PowerShell</b></li>
  <li><b>Windows 10</b></li>
</ul>

<h2>Outcome</h2>
<p>
This lab simulates real-world attacks, detects them in a SIEM platform, enriches the data with location, and visualizes the attacks on a global map. It's a hands-on SOC/SIEM training setup using free Azure resources.
</p>
