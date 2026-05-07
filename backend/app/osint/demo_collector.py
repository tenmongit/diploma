from typing import Any


_CITY_PROFILES = {
    "almaty": {"city": "Almaty", "lat": 43.2389, "lon": 76.8897},
    "astana": {"city": "Astana", "lat": 51.1605, "lon": 71.4704},
    "shymkent": {"city": "Shymkent", "lat": 42.3417, "lon": 69.5901},
    "karaganda": {"city": "Karaganda", "lat": 49.8068, "lon": 73.0851},
    "aktobe": {"city": "Aktobe", "lat": 50.2839, "lon": 57.1670},
}


class DemoCollector:
    name = "demo"

    def collect(self, target_domain: str) -> list[dict[str, Any]]:
        domain = target_domain.strip().lower()
        profile = self._profile_for_domain(domain)
        city_slug = profile["city"].lower().replace(" ", "-")
        geolocation = {
            "lat": profile["lat"],
            "lon": profile["lon"],
            "city": profile["city"],
            "country": "Kazakhstan",
            "source": "demo_dataset",
            "evidence_type": "demo",
            "is_demo": True,
        }
        return [
            {
                "ip_address": f"10.250.{len(city_slug)}.10",
                "hostnames": [f"traffic-control.{domain}"],
                "geolocation": geolocation,
                "services": [
                    self._service(443, "https", "Sergek traffic monitoring dashboard TLS 1.0", "Sergek", {"version": "TLS 1.0"}),
                    self._service(80, "http", "Sergek public dashboard web interface", "Sergek"),
                ],
            },
            {
                "ip_address": f"10.250.{len(city_slug)}.20",
                "hostnames": [f"camera-gateway.{domain}"],
                "geolocation": geolocation,
                "services": [
                    self._service(554, "tcp", "RTSP Hikvision video stream endpoint", "Hikvision"),
                    self._service(80, "http", "Hikvision DVR web management interface", "Hikvision"),
                ],
            },
            {
                "ip_address": f"10.250.{len(city_slug)}.30",
                "hostnames": [f"iot-gateway.{domain}"],
                "geolocation": geolocation,
                "services": [
                    self._service(1883, "tcp", "MQTT Mosquitto smart city telemetry broker", "Mosquitto"),
                    self._service(8080, "http", "iot-gateway management console", "IoT-Gateway"),
                ],
            },
            {
                "ip_address": f"10.250.{len(city_slug)}.40",
                "hostnames": [f"parking-api.{domain}"],
                "geolocation": geolocation,
                "services": [
                    self._service(443, "https", "Parking API HTTPS service", "SmartParking", {"version": "TLS 1.2"}),
                ],
            },
            {
                "ip_address": f"10.250.{len(city_slug)}.50",
                "hostnames": [f"scada-demo.{domain}"],
                "geolocation": geolocation,
                "services": [
                    self._service(502, "tcp", "Modbus TCP city infrastructure telemetry endpoint", "Modbus"),
                ],
            },
        ]

    def _profile_for_domain(self, domain: str) -> dict[str, Any]:
        for key, profile in _CITY_PROFILES.items():
            if key in domain:
                return profile
        return _CITY_PROFILES["astana"]

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
