import requests


def check_ip_reputation(ip_address):
    API_KEY = "9755541c7bc0c00cef6a982778ffc0509164bf3b97fc3b1686e6392620f0f3a70117c4106c61a3ba"

    # No verificar IPs locales o sin clave
    if not API_KEY or ip_address.startswith('192.168.') or ip_address.startswith('10.') or ip_address == '127.0.0.1':
        return False

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip_address,
                "maxAgeInDays": 90
            },
            timeout=5
        )

        if response.status_code == 200:
            data = response.json().get('data', {})
            return data.get('abuseConfidenceScore') > 60  # Umbral de riesgo
    except requests.RequestException:
        pass

    return False


print(check_ip_reputation("103.228.136.100"))
