<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
 </head>
<body>

<h1>🚀 Network Traffic Analysis and Packet Capture Tool</h1>

<h2>📌 Overview</h2>

<p>
    The <b>Network Traffic Analysis and Packet Capture Tool</b> is a powerful security utility that allows users to capture, analyze, and monitor live network traffic.
    It provides real-time insights into packet flows, enabling security teams to investigate network activity, detect anomalies, and perform forensic analysis.
    The tool leverages raw sockets to capture packets and extract key information such as source/destination IP addresses, protocols, and payloads.
</p>

<h3>🔹 Key Capabilities:</h3>
<ul>
    <li>✅ <b>Live Packet Capture:</b> Captures packets directly from a network interface.</li>
    <li>✅ <b>IP Header Decoding:</b> Extracts and displays source and destination addresses.</li>
    <li>✅ <b>Real-Time Display:</b> Prints packet summaries as they are captured.</li>
    <li>✅ <b>Extensible Filtering:</b> Supports easy extension for deeper protocol analysis.</li>
    <li>✅ <b>Forensic Analysis:</b> Saves packet data for offline investigation.</li>
</ul>

<h2>🎯 Key Features</h2>

<h3>📡 Packet Capture</h3>
<ul>
    <li>Uses raw sockets to capture all network traffic on a specified interface.</li>
    <li>Requires root privileges for full packet access.</li>
    <li>Captures Ethernet, IPv4, IPv6, TCP, UDP, and ICMP packets.</li>
</ul>

<h3>🔍 IP Header Decoding</h3>
<ul>
    <li>Extracts essential information from each packet:</li>
    <ul>
        <li>➡ <b>Source IP Address</b></li>
        <li>➡ <b>Destination IP Address</b></li>
        <li>➡ <b>Protocol Type</b> (TCP, UDP, ICMP, etc.)</li>
        <li>➡ <b>Packet Length</b></li>
    </ul>
</ul>

<h3>📊 Real-Time Display</h3>
<ul>
    <li>Prints packet information to the console in real time.</li>
    <li>Allows security teams to monitor active connections and data flows.</li>
</ul>

<h3>⚙️ Extensible Filtering</h3>
<ul>
    <li>Users can define custom filtering rules.</li>
    <li>Filters packets by <b>IP address, protocol, or port number</b>.</li>
</ul>

<h3>🛠 Forensic Analysis</h3>
<ul>
    <li>Stores captured packets in a structured log file for offline analysis.</li>
    <li>Can be integrated with external network forensics tools.</li>
</ul>

<h2>📥 Installation</h2>

<h3>📌 Prerequisites</h3>
<ul>
    <li>Python <b>3.8+</b> is required.</li>
    <li>Must run with root privileges to access raw network packets.</li>
</ul>

<h3>📌 Clone the Repository</h3>
<pre>
<code>git clone https://github.com/yourusername/Cybersecurity-Portfolio.git
cd Cybersecurity-Portfolio/7_Network_Traffic_Analyzer</code>
</pre>

<h2>⚙️ Configuration</h2>

<table border="1">
    <tr>
        <th>Setting</th>
        <th>Description</th>
        <th>Default Value</th>
    </tr>
    <tr>
        <td><b>Network Interface</b></td>
        <td>Specifies the network interface for capturing packets.</td>
        <td>eth0</td>
    </tr>
    <tr>
        <td><b>Log File</b></td>
        <td>File where captured packets are stored for later analysis.</td>
        <td>packets.log</td>
    </tr>
    <tr>
        <td><b>Protocol Filter</b></td>
        <td>Filter packets by protocol (TCP, UDP, ICMP).</td>
        <td>None</td>
    </tr>
</table>

<h2>🚀 Usage</h2>

<h3>🔹 Start Packet Capture</h3>
<p>To begin capturing network packets on a specified interface:</p>
<pre>
<code>sudo python packet_sniffer.py --interface eth0</code>
</pre>

<h3>🔹 Filter Packets by Protocol</h3>
<p>To capture only TCP packets:</p>
<pre>
<code>sudo python packet_sniffer.py --interface eth0 --protocol TCP</code>
</pre>

<h3>🔹 Save Packets for Offline Analysis</h3>
<p>To log all captured packets to a file:</p>
<pre>
<code>sudo python packet_sniffer.py --interface eth0 --log packets.log</code>
</pre>

<h2>🏗 Architecture Overview</h2>

<p>The <b>Network Traffic Analysis and Packet Capture Tool</b> consists of multiple modular components:</p>

<ul>
    <li><b>📡 Packet Capture Engine:</b> Uses raw sockets to capture packets.</li>
    <li><b>🔍 Protocol Decoder:</b> Extracts relevant data from packet headers.</li>
    <li><b>📊 Real-Time Display Module:</b> Prints packet summaries to the console.</li>
    <li><b>📋 Logging Module:</b> Stores captured packet data for later analysis.</li>
    <li><b>⚙️ Filter Module:</b> Allows users to filter packets by IP, port, or protocol.</li>
</ul>

<p>📌 <b>Architecture Diagram:</b> See <b>docs/architecture.png</b> for details.</p>

<h2>📊 Sample Output</h2>

<h3>📄 Captured Packet Example:</h3>

<pre>
[2024-02-14 16:10:15] Captured Packet:
    Source IP: 192.168.1.100
    Destination IP: 8.8.8.8
    Protocol: TCP
    Packet Length: 74 bytes
</pre>

<h3>📈 Network Analysis Report:</h3>
<p>📌 See <b>docs/sample_packet_capture.png</b> for real packet logs.</p>

<h2>🎯 Contributing</h2>

<p>🚀 Contributions are welcome! If you'd like to contribute:</p>

<ol>
    <li>Fork the repository.</li>
    <li>Create a feature branch.</li>
    <li>Commit changes following best practices.</li>
    <li>Submit a pull request.</li>
</ol>

<p>🔹 Ensure that your code follows <b>PEP8</b> guidelines and includes <b>unit tests</b> before submitting.</p>

<h2>📜 License</h2>

<p>This project is licensed under the <b>MIT License</b>. See the <b>LICENSE</b> file for details.</p>

<h2>🛠 Future Enhancements</h2>

<ul>
    <li>✔ Integration with <b>Intrusion Detection Systems (IDS)</b>.</li>
    <li>✔ Machine Learning-based <b>Traffic Anomaly Detection</b>.</li>
    <li>✔ Support for <b>Deep Packet Inspection (DPI)</b>.</li>
    <li>✔ Web-based <b>Real-Time Packet Monitoring Dashboard</b>.</li>
</ul>

<h2>🚀 Developed for security professionals, network engineers, and cybersecurity analysts.</h2>
<h3>Monitor and Analyze Your Network Traffic with Confidence! 🔥</h3>

</body>
</html>
