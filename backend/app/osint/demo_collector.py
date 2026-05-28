from typing import Any


_CITY_PROFILES = {
    "almaty": {"city": "Almaty", "lat": 43.2389, "lon": 76.8897},
    "astana": {"city": "Astana", "lat": 51.1605, "lon": 71.4704},
    "shymkent": {"city": "Shymkent", "lat": 42.3417, "lon": 69.5901},
    "karaganda": {"city": "Karaganda", "lat": 49.8068, "lon": 73.0851},
    "aktobe": {"city": "Aktobe", "lat": 50.2839, "lon": 57.1670},
}


_ASSET_TEMPLATES = [
    ("traffic-control", -0.028, -0.035, [
        (443, "https", "Sergek traffic monitoring dashboard TLS 1.0 license plate tracking", "Sergek", {"version": "TLS 1.0"}),
        (80, "http", "Sergek public dashboard web interface", "Sergek", None),
    ]),
    ("camera-gateway-north", -0.020, 0.018, [
        (554, "tcp", "RTSP Hikvision video stream endpoint face recognition", "Hikvision", None),
        (80, "http", "Hikvision DVR web management interface", "Hikvision", None),
    ]),
    ("camera-gateway-south", 0.024, -0.014, [
        (554, "tcp", "RTSP Dahua video stream endpoint license plate tracking", "Dahua", None),
        (80, "http", "Dahua NVR web management interface", "Dahua", None),
    ]),
    ("intersection-camera-01", 0.011, 0.032, [
        (554, "tcp", "RTSP Axis camera video stream endpoint", "Axis", None),
    ]),
    ("intersection-camera-02", -0.038, 0.009, [
        (554, "tcp", "RTSP Vivotek smart traffic video stream", "Vivotek", None),
    ]),
    ("iot-gateway-central", 0.034, 0.041, [
        (1883, "tcp", "MQTT Mosquitto smart city telemetry broker location data", "Mosquitto", None),
        (8080, "http", "iot-gateway management console", "IoT-Gateway", None),
    ]),
    ("iot-gateway-east", -0.044, 0.052, [
        (1883, "tcp", "MQTT Mosquitto environmental sensor telemetry broker", "Mosquitto", None),
    ]),
    ("parking-api", 0.047, -0.048, [
        (443, "https", "Parking API HTTPS service TLS 1.2 license plate records", "SmartParking", {"version": "TLS 1.2"}),
    ]),
    ("parking-kiosk-01", -0.052, -0.018, [
        (23, "tcp", "Telnet parking kiosk maintenance console", "GoAhead", None),
        (80, "http", "GoAhead embedded parking kiosk web server", "GoAhead", None),
    ]),
    ("scada-water", 0.059, 0.010, [
        (502, "tcp", "Modbus TCP water pumping station telemetry endpoint", "Modbus", None),
    ]),
    ("scada-power", -0.061, 0.028, [
        (502, "tcp", "Modbus TCP street lighting controller telemetry endpoint", "Modbus", None),
    ]),
    ("opcua-utility", 0.070, -0.030, [
        (4840, "tcp", "OPC-UA utility automation server", "OPC-UA", None),
    ]),
    ("snmp-network-core", -0.073, -0.044, [
        (161, "udp", "SNMP public community network monitoring endpoint", "Cisco", None),
    ]),
    ("bus-tracker-api", 0.018, -0.066, [
        (80, "http", "Public bus tracking dashboard location data", "TransitOS", None),
    ]),
    ("emergency-camera", -0.015, 0.074, [
        (554, "tcp", "RTSP Hikvision emergency response camera face recognition", "Hikvision", None),
        (8443, "https", "Self-signed camera administration portal", "Hikvision", None),
    ]),
    ("air-quality-gateway", 0.083, 0.055, [
        (1883, "tcp", "MQTT Mosquitto air quality sensor telemetry broker", "Mosquitto", None),
    ]),
    ("smart-lighting", -0.086, 0.063, [
        (8080, "http", "iot-gateway smart lighting management console", "IoT-Gateway", None),
        (23, "tcp", "Telnet smart lighting maintenance shell", "GoAhead", None),
    ]),
    ("public-wifi-controller", 0.091, -0.071, [
        (21, "tcp", "FTP public WiFi controller backup service", "GoAhead", None),
        (80, "http", "GoAhead embedded web server", "GoAhead", None),
    ]),
]


class DemoCollector:
    name = "demo"

    def collect(self, target_domain: str) -> list[dict[str, Any]]:
        domain = target_domain.strip().lower() or "demo.local"
        focused_profile = self._profile_for_domain(domain)
        profiles = [focused_profile] if focused_profile else list(_CITY_PROFILES.values())
        hosts = []

        for city_index, profile in enumerate(profiles, start=1):
            city_slug = profile["city"].lower().replace(" ", "-")
            demo_domain = domain if focused_profile else f"{city_slug}.{domain}"
            for asset_index, (hostname, lat_offset, lon_offset, services) in enumerate(_ASSET_TEMPLATES, start=1):
                hosts.append({
                    "ip_address": f"10.250.{city_index}.{asset_index}",
                    "hostnames": [f"{hostname}.{demo_domain}"],
                    "geolocation": self._geolocation(profile, lat_offset, lon_offset),
                    "services": [
                        self._service(port, protocol, banner, product, tls)
                        for port, protocol, banner, product, tls in services
                    ],
                })

        return hosts

    def _profile_for_domain(self, domain: str) -> dict[str, Any] | None:
        for key, profile in _CITY_PROFILES.items():
            if key in domain:
                return profile
        return None

    def _geolocation(
        self,
        profile: dict[str, Any],
        lat_offset: float,
        lon_offset: float,
    ) -> dict[str, Any]:
        return {
            "lat": round(profile["lat"] + lat_offset, 6),
            "lon": round(profile["lon"] + lon_offset, 6),
            "city": profile["city"],
            "country": "Kazakhstan",
            "source": "demo_dataset",
            "evidence_type": "demo",
            "is_demo": True,
        }

    def _service(
        self,
        port: int,
        protocol: str,
        banner: str,
        product: str,
        tls: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        banner_data = {
            "banner": banner,
            "product": product,
            "source": "demo_dataset",
            "evidence_type": "demo",
            "is_demo": True,
        }
        if tls:
            banner_data["tls"] = tls
        return {
            "port": port,
            "protocol": protocol,
            "service_name": product.lower(),
            "banner_data": banner_data,
        }
