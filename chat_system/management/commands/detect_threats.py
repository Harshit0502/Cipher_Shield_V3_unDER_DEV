from django.core.management.base import BaseCommand
import pandas as pd
import joblib
import os

class Command(BaseCommand):
    help = "Detect suspicious users based on behavior data and trained ML model."

    def handle(self, *args, **kwargs):
        try:
            self.stdout.write(self.style.SUCCESS("🚀 Starting Threat Detection..."))

            # Load user features
            if not os.path.exists('extended_user_features_5000.csv'):
                self.stdout.write(self.style.ERROR("❌ Features CSV file not found. Please upload 'extended_user_features_5000.csv'."))
                return

            df = pd.read_csv('extended_user_features_5000.csv')

            if df.empty:
                self.stdout.write(self.style.ERROR("❌ No user data found. Detection aborted."))
                return

            usernames = df['username']

            # Drop username for model input
            X = df.drop(columns=['username'])

            # Load trained model and scaler
            if not os.path.exists('rf_model.joblib') or not os.path.exists('scaler.joblib'):
                self.stdout.write(self.style.ERROR("❌ Model or scaler file not found. Train the model first."))
                return

            model = joblib.load('rf_model.joblib')
            scaler = joblib.load('scaler.joblib')

            X_scaled = scaler.transform(X)

            # Predict probabilities
            scores = model.predict_proba(X_scaled)[:, 1]  # Probability of being malicious

            # Collect suspicious users
            suspicious_users = []

            for i, score in enumerate(scores):
                threats = []
                user = usernames[i]

                if df.loc[i, 'msgs'] > 100:
                    threats.append('Flooding Detected')
                if df.loc[i, 'rate_limits'] > 5:
                    threats.append('Rate Limit Abuse')
                if df.loc[i, 'fails'] > 10:
                    threats.append('Brute Force Attempt')
                if score > 0.7:
                    threats.append('ML Threat Detected')

                if threats:
                    suspicious_users.append({
                        'username': user,
                        'threats': threats,
                        'ml_score': round(score, 3)
                    })

            # Save alerts
            if suspicious_users:
                with open('alerts.log', 'w') as alert_file:
                    for user_info in suspicious_users:
                        alert_text = f"User: {user_info['username']} | Threats: {', '.join(user_info['threats'])} | ML Score: {user_info['ml_score']}\n"
                        alert_file.write(alert_text)

                self.stdout.write(self.style.SUCCESS(f"✅ {len(suspicious_users)} suspicious users detected. Alerts saved to alerts.log."))
            else:
                self.stdout.write(self.style.SUCCESS("✅ No suspicious users detected."))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Error during threat detection: {str(e)}"))
