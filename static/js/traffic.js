// Traffic Generator - Simplified

let isRunning = false;
let eventSource = null;
let totalPackets = 0;
let pcapFileCount = 0;

const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const attackBtn = document.getElementById('attackBtn');
const dosBtn = document.getElementById('dosBtn');
const status = document.getElementById('status');
const packetCount = document.getElementById('packetCount');
const pcapCount = document.getElementById('pcapCount');
const packetList = document.getElementById('packet-list');

// Wyświetla pakiet w liście
function displayPacket(packet) {
    const isAttack = packet.attack_type !== undefined;
    const isFlow = packet.flow_type === 'bidirectional';
    const cardClass = isAttack ? 'card border-danger' : (isFlow ? 'card border-success' : 'card');
    const hasPcapSaved = packet.pcap_saved !== undefined;
    
    const sizeInfo = packet.packet_count 
        ? `${packet.packet_count} pkts, ${packet.total_size} bytes`
        : `${packet.packet_size || 0} bytes`;
    
    const packetHtml = `
        <div class="${cardClass} mb-2">
            <div class="card-body py-2">
                <div class="packet-info">
                    <strong>${packet.timestamp}</strong>
                    <br>
                    <span class="text-primary">${packet.source_ip}:${packet.source_port || 'N/A'}</span>
                    <span class="mx-2">↔</span>
                    <span class="text-danger">${packet.dest_ip}:${packet.dest_port || 'N/A'}</span>
                    <br>
                    <span class="badge bg-secondary">${packet.protocol}</span>
                    <span class="badge bg-info">${sizeInfo}</span>
                    ${isFlow ? '<span class="badge bg-success">Bidirectional</span>' : ''}
                    ${isAttack ? `<span class="badge bg-danger">${packet.attack_type}</span>` : ''}
                    ${hasPcapSaved ? '<span class="badge bg-warning text-dark">📄 PCAP saved</span>' : ''}
                </div>
            </div>
        </div>
    `;
    
    // Usuń placeholder
    const placeholder = packetList.querySelector('.text-muted');
    if (placeholder) placeholder.remove();
    
    // Dodaj na początku listy
    packetList.insertAdjacentHTML('afterbegin', packetHtml);
    
    // Ogranicz do 50 pakietów
    while (packetList.children.length > 50) {
        packetList.lastElementChild.remove();
    }
    
    // Aktualizuj liczniki
    totalPackets++;
    packetCount.textContent = `Flows: ${totalPackets}`;
    
    if (hasPcapSaved) {
        pcapFileCount++;
        pcapCount.textContent = `PCAP files: ${pcapFileCount}`;
    }
}

// Start generatora z SSE
function startGenerator() {
    if (isRunning) return;
    
    fetch('/traffic/api/start/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    });
    
    isRunning = true;
    startBtn.disabled = true;
    stopBtn.disabled = false;
    status.textContent = 'Running';
    status.className = 'badge bg-success';
    
    eventSource = new EventSource('/traffic/api/stream/');
    
    eventSource.onmessage = function(event) {
        const packet = JSON.parse(event.data);
        displayPacket(packet);
    };
    
    eventSource.onerror = function() {
        stopGenerator();
    };
}

// Stop generatora
function stopGenerator() {
    if (!isRunning) return;
    
    isRunning = false;
    startBtn.disabled = false;
    stopBtn.disabled = true;
    status.textContent = 'Stopped';
    status.className = 'badge bg-secondary';
    
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
    
    fetch('/traffic/api/stop/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(response => response.json())
    .then(data => {
        if (data.final_pcap) {
            pcapFileCount++;
            pcapCount.textContent = `PCAP files: ${pcapFileCount}`;
        }
    });
}

// Symulacja ataku
function simulateAttack(attackType = 'syn_flood') {
    const count = attackType === 'dos' ? 50 : 10;
    
    fetch(`/traffic/api/attack/?count=${count}&type=${attackType}`)
        .then(response => response.json())
        .then(data => {
            data.packets.forEach(packet => displayPacket(packet));
            pcapFileCount += data.pcap_files_saved || 0;
            pcapCount.textContent = `PCAP files: ${pcapFileCount}`;
        });
}

// Event listeners
startBtn.addEventListener('click', startGenerator);
stopBtn.addEventListener('click', stopGenerator);
attackBtn.addEventListener('click', () => simulateAttack('syn_flood'));
dosBtn.addEventListener('click', () => simulateAttack('dos'));
