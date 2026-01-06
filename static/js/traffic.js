// Traffic Generator

let isRunning = false;
let pollInterval = null;
let eventSource = null;

const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const attackBtn = document.getElementById('attackBtn');
const status = document.getElementById('status');
const packetCount = document.getElementById('packetCount');
const packetList = document.getElementById('packet-list');

// Funkcja do wyświetlania pakietu
function displayPacket(packet) {
    const isAttack = packet.attack_type !== undefined;
    const cardClass = isAttack ? 'packet-card attack' : 'packet-card';
    
    const packetHtml = `
        <div class="card ${cardClass}">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div class="packet-info">
                        <strong>${packet.timestamp}</strong>
                        <br>
                        <span class="text-primary">${packet.source_ip}:${packet.source_port || 'N/A'}</span>
                        <span class="mx-2">→</span>
                        <span class="text-danger">${packet.dest_ip}:${packet.dest_port || 'N/A'}</span>
                        <br>
                        <span class="badge bg-secondary">${packet.protocol}</span>
                        <span class="badge bg-info">${packet.packet_size} bytes</span>
                        ${isAttack ? `<span class="status-badge status-attack">${packet.attack_type}</span>` : ''}
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Dodaj na początku listy
    packetList.insertAdjacentHTML('afterbegin', packetHtml);
    
    // Ograniczenie do 50 pakietów na ekranie
    const packets = packetList.querySelectorAll('.packet-card');
    if (packets.length > 50) {
        packets[packets.length - 1].remove();
    }
}

// Funkcja do pobierania pakietów (polling)
function fetchPackets() {
    fetch('/traffic/api/packets/')
        .then(response => response.json())
        .then(data => {
            packetCount.textContent = `Packets: ${data.total}`;
            
            // Wyświetl tylko nowe pakiety (można dodać logikę śledzenia ostatniego)
            if (data.packets && data.packets.length > 0) {
                // Wyświetl ostatni pakiet (najnowszy)
                const lastPacket = data.packets[data.packets.length - 1];
                displayPacket(lastPacket);
            }
        })
        .catch(error => {
            console.error('Error fetching packets:', error);
        });
}

// Start generatora używając Server-Sent Events
function startGenerator() {
    if (isRunning) return;
    
    isRunning = true;
    startBtn.disabled = true;
    stopBtn.disabled = false;
    status.textContent = 'Running';
    status.className = 'badge bg-success';
    
    // Użyj Server-Sent Events do streamowania
    eventSource = new EventSource('/traffic/api/stream/');
    
    eventSource.onmessage = function(event) {
        const packet = JSON.parse(event.data);
        displayPacket(packet);
        packetCount.textContent = `Packets: ${parseInt(packetCount.textContent.split(':')[1]) + 1 || 1}`;
    };
    
    eventSource.onerror = function(error) {
        console.error('SSE error:', error);
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
    
    if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
    }
}

// Symulacja ataku
function simulateAttack() {
    fetch('/traffic/api/attack/?count=10')
        .then(response => response.json())
        .then(data => {
            data.packets.forEach(packet => {
                displayPacket(packet);
            });
            packetCount.textContent = `Packets: ${parseInt(packetCount.textContent.split(':')[1]) + data.packets_generated || data.packets_generated}`;
        })
        .catch(error => {
            console.error('Error generating attack:', error);
        });
}

// Event listeners
startBtn.addEventListener('click', startGenerator);
stopBtn.addEventListener('click', stopGenerator);
attackBtn.addEventListener('click', simulateAttack);
