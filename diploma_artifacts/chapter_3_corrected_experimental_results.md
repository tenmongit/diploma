# 3. Experimental Results

## 3.1 Validation Methodology

Because official regulations, institutional ethics, and responsible-disclosure principles prohibit active assessment of municipal infrastructure owned or operated by the state, the SmartCity OSINT Platform was validated through a controlled internal self-assessment methodology rather than conventional third-party penetration testing. The purpose of this validation was to assess the correctness, reliability, and practical usefulness of the automated collection, classification, risk scoring, and visualization pipeline without interfering with real network functionality.

The validation followed a passive-only methodology. The platform did not perform exploitation, brute forcing, credential testing, port scanning, direct TCP/UDP probing, or vulnerability confirmation against municipal infrastructure. Instead, it processed passive OSINT records, Certificate Transparency data, DNS-derived records, Shodan hostname results when available, and a controlled smart-city scenario dataset designed to exercise the same classification and scoring pipeline safely.

The analytical output of the system was evaluated against two conceptual frameworks. First, technical exposure was interpreted through common industrial-control and smart-city security concepts, including exposed management interfaces, legacy protocols, video-streaming endpoints, telemetry brokers, and industrial automation protocols. Second, privacy impact was evaluated using LINDDUN-inspired categories, especially Linkability, Identifiability, and Non-Repudiation. These categories are represented in the implementation through privacy tags such as `P:L`, `P:I`, `P:NR`, `video_surveillance`, `iot_data`, `traffic_monitoring`, and `industrial_control`.

A manual verification procedure was performed to evaluate the Rule-Based Classification Engine. The available classified service records stored in PostgreSQL were inspected together with their raw banner metadata, product names, port numbers, and assigned categories. The verification focused on whether services were assigned reasonable categories such as `Surveillance Node`, `IoT MQTT Broker`, `SCADA/Modbus Endpoint`, `Camera Web UI`, `Embedded Web Server`, and `Telnet Service (Insecure)`. This review was used to assess whether the IF-THEN regex logic reduced false positives. For example, a generic HTTP service should not be classified as an IoT gateway unless its banner or product metadata contains infrastructure-specific indicators such as `iot-gateway`, camera-related strings, or known embedded-device product names.

The classification engine is implemented as a deterministic rule set based on service port and banner/product regular-expression matching. Each service is passed through the same logic before being persisted in the database. This makes the validation reproducible, because the same input banner and product metadata always produce the same classification and privacy tags.

The risk scoring model was validated by checking whether services with higher technical and privacy exposure received higher scores. The implemented scoring engine combines port exposure, protocol security, known vulnerable product indicators, privacy-impact weights, and personally identifiable information indicators. Scores are mapped to four severity levels: Low, Medium, High, and Critical.

## 3.2 Quantitative Results

The current local PostgreSQL database snapshot contains the following experimental records:

| Metric | Value |
|---|---:|
| Completed scan jobs | 19 |
| Host rows | 50 |
| Unique IP addresses | 34 |
| Classified service rows | 71 |
| Vulnerability/risk rows | 84 |
| Vendor records | 15 |
| Average completed scan duration | 58 seconds |

These values represent the current development and validation state of the prototype. They should be interpreted as experimental validation metrics rather than claims of large-scale compromise or verified exploitation of municipal systems.

The most recent controlled city-scale scenario run produced the following result:

| Metric | Value |
|---|---:|
| Scan ID | 19 |
| Target profile | Almaty city-scale infrastructure scenario |
| Hosts | 18 |
| Unique IP addresses | 18 |
| Services | 26 |
| Vulnerability/risk rows | 32 |

The controlled scenario dataset models smart-city infrastructure components such as traffic-monitoring dashboards, surveillance gateways, RTSP camera streams, MQTT telemetry brokers, parking systems, Modbus utility endpoints, OPC-UA automation services, SNMP monitoring endpoints, smart-lighting controllers, and public Wi-Fi controllers. These records are processed by the same backend pipeline as passive OSINT records: they are normalized, classified, scored, persisted in PostgreSQL, and visualized on the dashboard and threat map.

### Severity Distribution

Across the current local database, the severity distribution of vulnerability/risk rows is:

| Severity | Count | Percentage |
|---|---:|---:|
| Critical | 37 | 44.0% |
| High | 15 | 17.9% |
| Medium | 15 | 17.9% |
| Low | 17 | 20.2% |

For the most recent controlled city-scale run, the distribution was:

| Severity | Count |
|---|---:|
| Critical | 18 |
| High | 6 |
| Medium | 5 |
| Low | 3 |

The relatively high proportion of Critical results is expected in the controlled validation scenario, because the dataset intentionally includes high-impact smart-city exposure patterns such as video surveillance, location tracking, license-plate-related banners, legacy remote administration protocols, and industrial-control protocols. These records are used to test whether the risk engine correctly escalates services that combine technical exposure with privacy impact.

### Classification Distribution

The most common service classifications in the current database are:

| Classification | Service Count |
|---|---:|
| HTTPS Service | 10 |
| Surveillance Node | 10 |
| IoT MQTT Broker | 7 |
| Camera Web UI | 6 |
| IoT Gateway | 6 |
| SCADA/Modbus Endpoint | 6 |
| Embedded Web Server | 5 |
| Sergek Dashboard | 5 |
| Telnet Service (Insecure) | 5 |

This distribution demonstrates that the validation dataset exercises several important smart-city categories: surveillance systems, IoT telemetry, industrial-control protocols, legacy management interfaces, and web-exposed embedded systems.

### Port and Protocol Distribution

The most frequent exposed service categories by port/protocol are:

| Port/Protocol | Count | Interpretation |
|---|---:|---|
| 554/tcp | 12 | RTSP/video-streaming exposure |
| 80/tcp | 9 | Web interface exposure |
| 80/http | 8 | HTTP web service records |
| 443/tcp | 8 | HTTPS service records |
| 1883/tcp | 7 | MQTT telemetry exposure |
| 502/tcp | 6 | Modbus/industrial-control exposure |
| 23/tcp | 5 | Telnet legacy administration |

The presence of RTSP, MQTT, Modbus, Telnet, and embedded web services confirms that the experimental dataset is suitable for evaluating smart-city exposure scenarios.

### CVE and Privacy-Risk Findings

The vulnerability table contains both CVE-associated findings and privacy-risk findings without a specific CVE. The most frequent finding types are:

| Finding Type | Count |
|---|---:|
| Privacy-risk finding | 41 |
| CVE-2017-7921 | 11 |
| CVE-2021-36260 | 11 |
| CVE-2017-17562 | 8 |
| CVE-2021-33044 | 7 |
| CVE-2020-25078 | 6 |

This reflects the platform’s dual-purpose scoring approach. Some findings are associated with known vulnerable product indicators, while others represent privacy or exposure risks identified through service classification and LINDDUN-inspired tags.

### Performance and Resource Behavior

The asynchronous Celery architecture proved appropriate for the prototype’s workload. Scans are dispatched as background tasks, allowing the FastAPI backend and React frontend to remain responsive while collection and processing continue. Progress is persisted in PostgreSQL and displayed through the scan page.

In the current local database, completed scans show an average runtime of approximately 58 seconds. This value reflects the present development environment and the mixture of controlled scenario scans and lightweight passive OSINT runs. It should not be generalized as a universal performance benchmark for all real-world targets, because real passive OSINT runtime depends on API response time, Shodan rate limits, network latency, result volume, and database persistence cost.

## 3.3 Qualitative Analysis

The qualitative evaluation focused on whether the platform correctly prioritizes services that combine technical exposure with smart-city privacy impact. The results show that the system does not treat all open services equally. Instead, the Risk Scoring Engine increases severity when a service is associated with sensitive infrastructure or privacy-relevant data flows.

For example, an ordinary HTTPS service receives a low base exposure score. However, a camera-related RTSP stream, a traffic-monitoring dashboard, a parking-system interface, or an MQTT broker containing location-data indicators receives additional privacy-impact weight. This is important because smart-city systems may affect citizens even when a direct exploit has not been confirmed. A video-streaming or license-plate-related service can create Identifiability and Linkability risks beyond ordinary network exposure.

The highest-risk categories observed during validation were associated with the following patterns:

| Pattern | Risk Reason |
|---|---|
| RTSP and camera-related banners | Potential video surveillance and identifiability impact |
| MQTT telemetry brokers | Possible location or sensor-data exposure |
| Telnet and FTP services | Plaintext legacy management protocols |
| Modbus and OPC-UA services | Industrial-control or utility automation exposure |
| GoAhead embedded web services | Known vulnerable embedded web-server indicator |
| Hikvision/Dahua product indicators | Known CVE mappings and surveillance-system context |
| Weak TLS or self-signed service metadata | Weak cryptographic posture |

The qualitative analysis confirms that the platform’s value is not limited to listing open ports. Its main contribution is the contextual interpretation of exposed services in smart-city environments. The same technical exposure may receive a higher priority when linked to surveillance, traffic monitoring, telemetry, or industrial-control contexts.

## Recommendations Prioritization Matrix

Based on the experimental results, the following prioritization matrix can support municipal administrators and SOC teams.

### Immediate Remediation: Critical Priority

Critical OT, IoT, and surveillance assets should be removed from direct public exposure. Examples include RTSP camera streams, MQTT brokers carrying telemetry, Modbus/OPC-UA automation endpoints, and management interfaces for traffic or surveillance systems. These assets should be placed behind network segmentation, VPN access, private APNs, firewall allowlists, or zero-trust access controls.

### Short-Term Remediation: High Priority

Legacy management protocols should be deprecated. Telnet on TCP/23, FTP on TCP/21, and unencrypted HTTP administration panels should be replaced with SSH, HTTPS, modern TLS configurations, and strong authentication. Embedded web interfaces should be reviewed for vendor patches and default credentials.

### Ongoing Strategy: Medium Priority

Municipalities should maintain a firmware and supply-chain auditing program for imported surveillance, IoT, and embedded infrastructure devices. Procurement requirements should include patch support, vulnerability disclosure procedures, secure configuration baselines, and regular review of exposed services.

### Continuous Monitoring: Low Priority

Lower-risk services should remain part of asset inventory and continuous passive monitoring. Even low-severity exposure can become important when combined with new vulnerabilities, misconfiguration, or changes in service context.

## Limitations and Constraints Identified During Testing

The prototype demonstrates the feasibility of passive OSINT-based threat mapping for smart-city infrastructure. However, several limitations were identified.

First, the project is strictly passive. The platform does not actively probe discovered devices and therefore cannot confirm exploitability, authentication requirements, or real compromise. Findings must be interpreted as risk indicators rather than verified intrusions.

Second, the real OSINT mode is constrained by free-tier Shodan access. The current implementation uses hostname-based queries such as `hostname:"<target_domain>"`. Advanced queries based on city, country, organization, product, and port may require paid API access and are not relied upon as the main collection mechanism.

Third, domain-based collection may miss shadow infrastructure that is not linked to official municipal hostnames, certificate records, or discoverable DNS names. As a result, the platform is more effective at finding infrastructure tied to known domains than standalone IP-based assets.

Fourth, some validation records are controlled scenario data. This is necessary for ethical and reproducible evaluation, but it must be clearly distinguished in academic analysis from confirmed real-world municipal exposure. The controlled dataset is useful for validating the classification, scoring, persistence, and visualization pipeline, but it should not be presented as evidence of actual compromise.
