// script.js mejorado
const domainInput = document.getElementById('domainInput');
const lookupButton = document.getElementById('lookupButton');
const resultsDiv = document.getElementById('results');

// Configuración
const CLOUDFLARE_ASN = 'AS13335';
const IPINFO_TOKEN = '4a68441ece1b8c'; // 

// Lista ampliada de subdominios
let commonSubdomains = [
    'origin', 'direct', 'old', 'server', 'mx', 'srv', 'dns', 'ns', 'backend',
    'www', 'mail', 'blog', 'ftp', 'cpanel', 'webmail', 'shop', 'dev', 'staging',
    'api', 'admin', 'portal', 'autodiscover', 'owa', 'vpn', 'm', 'support', 'test',
    'smtp', 'pop', 'imap', 'ns1', 'ns2', 'sql', 'db', 'files', 'secure', 'ns3', 
    'ns4', 'ns5', 'ns6', 'ns7', 'ns8', 'archivos', 'videos', 'pics', 'fotos', 
    'web', 'forum', 'help', 'direct', 'directconnect', 'panel', 'record', 'ssl'
];

lookupButton.addEventListener('click', fetchIpAddress);
domainInput.addEventListener('keypress', (e) => e.key === 'Enter' && fetchIpAddress());

// Función mejorada de DNS lookup con múltiples tipos
async function performDnsLookup(name, type = 'A') {
    try {
        const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
            headers: { 'accept': 'application/dns-json' },
        });

        if (!response.ok) return null;
        
        const data = await response.json();
        if (data.Status !== 0 || !data.Answer) return null;

        return data.Answer.filter(record => record.type === {
            'A': 1, 'MX': 15, 'TXT': 16}[type]).map(r => type === 'MX' ? 
            {priority: r.data.split(' ')[0], exchange: r.data.split(' ')[1]} : r.data);

    } catch (error) {
        console.error(`DNS lookup error (${type}):`, error);
        return null;
    }
}

// Análisis de registros SPF
function parseSPF(spfRecord) {
    const ips = [];
    const patterns = [
        /ip4:([\d\.\/]+)/g,
        /ip6:([\da-fA-F:\/]+)/g,
        /include:([\w\.\-]+)/g
    ];
    
    patterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(spfRecord)) !== null) {
            ips.push(match[1]);
        }
    });
    
    return ips;
}

// Verificación ASN usando ipinfo.io
async function checkASN(ip) {
    try {
        const response = await fetch(`https://ipinfo.io/${ip}/json?token=${IPINFO_TOKEN}`);
        const data = await response.json();
        return {
            asn: data.org || 'Desconocido',
            isCloudflare: data.org?.includes(CLOUDFLARE_ASN) || false
        };
    } catch (error) {
        return { asn: 'Error', isCloudflare: false };
    }
}

// Función principal mejorada
async function fetchIpAddress() {
    const domain = domainInput.value.trim().toLowerCase();
    if (!domain || !/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
        resultsDiv.innerHTML = '<p class="error">Dominio inválido</p>';
        return;
    }

    resultsDiv.innerHTML = '<p class="loading">Iniciando análisis avanzado...</p>';
    lookupButton.disabled = true;

    try {
        // 1. Búsqueda principal (A, MX, TXT)
        const [aRecords, mxRecords, txtRecords] = await Promise.all([
            performDnsLookup(domain, 'A'),
            performDnsLookup(domain, 'MX'),
            performDnsLookup(domain, 'TXT')
        ]);

        // 2. Procesar MX records
        let mxIps = [];
        if (mxRecords) {
            const mxResolutions = await Promise.all(
                mxRecords.map(mx => performDnsLookup(mx.exchange, 'A'))
            );
            mxIps = mxResolutions.flat().filter(ip => ip);
        }

        // 3. Procesar TXT (SPF)
        let spfIps = [];
        if (txtRecords) {
            const spfRecords = txtRecords.filter(r => r.startsWith('v=spf1'));
            spfIps = spfRecords.flatMap(r => parseSPF(r));
        }

        // 4. Subdominios
        const subdomainsIps = await checkSubdomains(domain);

        // 5. Unificar todas las IPs
        const allIps = [
            ...(aRecords || []),
            ...mxIps,
            ...spfIps,
            ...subdomainsIps
        ].filter((v, i, a) => a.indexOf(v) === i); // Eliminar duplicados

        // 6. Verificar ASN y filtrar
        const ipAnalysis = await Promise.all(
            allIps.map(async ip => ({
                ip,
                ...await checkASN(ip)
            }))
        );

        // 7. Mostrar resultados
        displayResults(domain, ipAnalysis.filter(ip => !ip.isCloudflare));

    } catch (error) {
        resultsDiv.innerHTML += `<p class="error">Error: ${error.message}</p>`;
    } finally {
        lookupButton.disabled = false;
    }
}

// Función para verificar subdominios
async function checkSubdomains(domain) {
    resultsDiv.innerHTML += '<p class="loading">Escaneando subdominios...</p>';
    
    const subdomainPromises = commonSubdomains.map(async sub => {
        const fullSubdomain = `${sub}.${domain}`;
        const aRecords = await performDnsLookup(fullSubdomain, 'A');
        return aRecords || [];
    });

    const subdomainsResults = await Promise.all(subdomainPromises);
    return subdomainsResults.flat();
}

// Mostrar resultados mejorados
function displayResults(domain, ipAnalysis) {
    let html = `<h3>Resultados para ${domain}</h3>`;
    
    if (ipAnalysis.length === 0) {
        html += '<p class="error">No se encontraron IPs potenciales fuera de Cloudflare</p>';
    } else {
        html += '<div class="results-grid">';
        ipAnalysis.forEach(({ ip, asn }) => {
            html += `
            <div class="ip-card">
                <div class="ip-header">${ip}</div>
                <div class="ip-info">
                    <span>ASN: ${asn}</span>
                    <a href="https://ipinfo.io/${ip}" target="_blank">DetaLLe de esta IP</a>
                </div>
            </div>`;
        });
        html += '</div>';
    }

    resultsDiv.innerHTML = html;
}
