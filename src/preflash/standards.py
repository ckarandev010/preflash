"""Standards each finding maps to. Provision / category / capability level only (no sub-clause IDs)."""

EN303645 = {
    "5.1": "5.1 No universal default passwords",
    "5.3": "5.3 Keep software updated",
    "5.4": "5.4 Securely store sensitive security parameters",
    "5.5": "5.5 Communicate securely",
    "5.6": "5.6 Minimize exposed attack surfaces",
    "5.7": "5.7 Ensure software integrity",
    "5.8": "5.8 Ensure that personal data is secure",
    "5.9": "5.9 Make systems resilient to outages",
    "5.13": "5.13 Validate input data",
}

OWASP_IOT = {
    "I1": "I1 Weak, guessable, or hardcoded passwords",
    "I2": "I2 Insecure network services",
    "I4": "I4 Lack of secure update mechanism",
    "I5": "I5 Use of insecure or outdated components",
    "I7": "I7 Insecure data transfer and storage",
    "I9": "I9 Insecure default settings",
    "I10": "I10 Lack of physical hardening",
}

NISTIR_8259A = {
    "ID": "Device identification",
    "CFG": "Device configuration",
    "DATA": "Data protection",
    "ACCESS": "Logical access to interfaces",
    "UPDATE": "Software update",
    "STATE": "Cybersecurity state awareness",
}


def expand(en=(), owasp=(), nist=()):
    return {
        "etsi_en_303_645": [EN303645[k] for k in en],
        "owasp_iot_top10_2018": [OWASP_IOT[k] for k in owasp],
        "nistir_8259a": [NISTIR_8259A[k] for k in nist],
    }
