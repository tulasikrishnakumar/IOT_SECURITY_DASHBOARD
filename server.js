const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { spawn, exec } = require('child_process');
const os = require('os');
const axios = require('axios');
const puppeteer = require('puppeteer');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(express.static('.'));

const MAC_API_KEY = "at_Y6uMaLoWiyOgFpEn9MDin3P4UMvxq";
let activeDevices = [];

const log = (socket, msg, type = 'info') => {
    socket.emit('terminal', { msg: `[${new Date().toLocaleTimeString()}] ${msg}`, type });
};

// --- DEEP NVD SEARCH ENGINE ---
async function fetchNVDVulnerabilities(services, vendor) {
    let allVulns = [];
    // Search by Vendor + Service pairs for high accuracy
    const searchTerms = [vendor, ...services.map(s => s.name)];
    
    for (const term of searchTerms.slice(0, 3)) { // Limit to top 3 signals to avoid API rate limits
        if (!term || term === "Generic" || term === "unknown") continue;
        try {
            const res = await axios.get(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${term}`, { timeout: 4000 });
            if (res.data.vulnerabilities) {
                const mapped = res.data.vulnerabilities.slice(0, 3).map(v => ({
                    id: v.cve.id,
                    severity: v.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || "HIGH",
                    desc: v.cve.descriptions.find(d => d.lang === 'en')?.value.substring(0, 150) + "..."
                }));
                allVulns.push(...mapped);
            }
        } catch (e) { continue; }
    }
    // Remove duplicates
    return [...new Map(allVulns.map(item => [item.id, item])).values()];
}

io.on('connection', (socket) => {
    socket.emit('interfaces', os.networkInterfaces());
    
    socket.on('scanNetwork', (range) => {
        log(socket, `INITIATING RECON: nmap -sn ${range}`, "command");
        const nmap = spawn('nmap', ['-sn', '--unprivileged', range]);
        nmap.stdout.on('data', (data) => {
            const ips = data.toString().match(/\d+\.\d+\.\d+\.\d+/g) || [];
            ips.forEach(ip => {
                if (!activeDevices.find(d => d.ip === ip)) {
                    exec(`arp -a ${ip}`, async (err, stdout) => {
                        const match = stdout.match(/([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})/);
                        const mac = match ? match[0].toUpperCase() : "Unknown";
                        const res = await axios.get(`https://api.macaddress.io/v1?apiKey=${MAC_API_KEY}&output=json&search=${mac}`).catch(() => ({data: {vendorDetails:{}}}));
                        const vendor = res.data.vendorDetails.companyName || "Unknown Vendor";
                        activeDevices.push({ ip, mac, vendor, isScanned: false, services: [], vulns: [], patch: "" });
                        io.emit('updateDevices', activeDevices);
                    });
                }
            });
        });
    });

    socket.on('auditDevice', (ip) => {
        log(socket, `DEEP AUDIT: nmap -sV -sC --version-light ${ip}`, "command");
        // -sV: Service version detection | -sC: Default script scan
        const nmap = spawn('nmap', ['-sV', '-sC', '--version-light', '--unprivileged', ip]);
        let output = '';
        nmap.stdout.on('data', d => {
            output += d.toString();
            log(socket, d.toString().trim());
        });

        nmap.on('close', async () => {
            // Parse Nmap Service Output
            const serviceLines = output.match(/\d+\/tcp\s+open\s+[\w\-?]+/g) || [];
            const detectedServices = serviceLines.map(line => {
                const parts = line.split(/\s+/);
                return { port: parts[0], name: parts[2] };
            });

            const idx = activeDevices.findIndex(d => d.ip === ip);
            if (idx !== -1) {
                const device = activeDevices[idx];
                log(socket, `Analyzing ${detectedServices.length} services against NVD database...`, "command");
                
                const vulns = await fetchNVDVulnerabilities(detectedServices, device.vendor);
                
                activeDevices[idx].isScanned = true;
                activeDevices[idx].services = detectedServices;
                activeDevices[idx].vulns = vulns;
                activeDevices[idx].patch = vulns.length > 0 ? 
                    `URGENT: Identified ${vulns.length} vulnerabilities. Update ${device.vendor} firmware and disable service: ${detectedServices[0]?.name || 'Unknown'}.` : 
                    "Service signatures appear standard. Ensure port-level firewalling is active.";
                
                io.emit('updateDevices', activeDevices);
                log(socket, `Audit Finished for ${ip}. Intelligence updated.`, "success");
            }
        });
    });

    socket.on('removeDevice', (ip) => {
        activeDevices = activeDevices.filter(d => d.ip !== ip);
        io.emit('updateDevices', activeDevices);
    });
});

server.listen(3000, () => console.log('Dashboard Live: http://localhost:3000'));