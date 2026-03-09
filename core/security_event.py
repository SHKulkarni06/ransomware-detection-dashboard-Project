from datetime import datetime

class SecurityEvent:

    def __init__(
        self,
        source,
        event_type,
        host,
        user,
        mitre_technique,
        tactic,
        impact,
        confidence,
        details
    ):

        self.timestamp = datetime.now()

        self.source = source
        self.event_type = event_type

        self.host = host
        self.user = user

        self.mitre_technique = mitre_technique
        self.tactic = tactic

        self.impact = impact
        self.confidence = confidence

        self.details = details

    def risk_score(self):
        return self.impact * (self.confidence / 10)

    def severity(self):

        score = self.risk_score()

        if score >= 25:
            return "CRITICAL"

        elif score >= 15:
            return "HIGH"

        elif score >= 7:
            return "MEDIUM"

        else:
            return "LOW"