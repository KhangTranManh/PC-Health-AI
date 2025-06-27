import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingRegressor
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, mean_squared_error
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import warnings
import os
warnings.filterwarnings('ignore')

class SecurityEnhancedComputerHealthAI:
    """AI system for comprehensive computer health and security diagnosis"""
    
    def __init__(self):
        self.health_classifier = None
        self.security_classifier = None
        self.performance_predictor = None
        self.security_predictor = None
        self.scaler = StandardScaler()
        self.computer_encoder = LabelEncoder()
        self.os_encoder = LabelEncoder()
        
        # Feature columns for the security-enhanced data
        self.feature_columns = [
            'cpu_percent', 'memory_percent', 'memory_used_gb', 'memory_total_gb',
            'disk_percent', 'disk_free_gb', 'disk_total_gb', 'process_count',
            'temperature', 'uptime_hours', 'network_sent_mb', 'network_recv_mb',
            'antivirus_enabled', 'real_time_protection', 'definition_age_days',
            'suspicious_activity_count', 'vulnerability_count', 'security_software_count'
        ]
        
    def load_security_data(self, csv_file_path):
        """Load and preprocess the security-enhanced monitoring data"""
        try:
            print(f"📊 Loading security data from {csv_file_path}...")
            
            # Try to load the security-enhanced data first
            if os.path.exists(csv_file_path):
                df = pd.read_csv(csv_file_path)
            else:
                # Fallback to look for any security files in data directory
                data_dir = "data"
                if os.path.exists(data_dir):
                    security_files = [f for f in os.listdir(data_dir) if 'security' in f and f.endswith('.csv')]
                    if security_files:
                        # Use the most recent security file
                        latest_file = max([os.path.join(data_dir, f) for f in security_files], 
                                        key=os.path.getmtime)
                        print(f"📁 Using latest security file: {latest_file}")
                        df = pd.read_csv(latest_file)
                    else:
                        raise FileNotFoundError("No security monitoring files found")
                else:
                    raise FileNotFoundError(f"Data directory not found: {data_dir}")
            
            print(f"✅ Loaded {len(df)} data points from {len(df['computer_name'].unique())} computers")
            
            # Convert timestamp to datetime
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Sort by timestamp
            df = df.sort_values(['computer_name', 'timestamp']).reset_index(drop=True)
            
            # Clean data
            df = df.fillna(0)  # Fill missing values
            
            # Add missing columns if they don't exist (for backwards compatibility)
            expected_columns = [
                'security_score', 'antivirus_enabled', 'real_time_protection',
                'definition_age_days', 'suspicious_activity_count', 'vulnerability_count',
                'security_software_count'
            ]
            
            for col in expected_columns:
                if col not in df.columns:
                    print(f"⚠️  Adding missing column: {col}")
                    if col == 'security_score':
                        df[col] = 85  # Default good security score
                    elif col in ['antivirus_enabled', 'real_time_protection']:
                        df[col] = True  # Assume enabled by default
                    else:
                        df[col] = 0  # Default to 0 for counts and ages
            
            print(f"📋 Computers in dataset: {', '.join(df['computer_name'].unique())}")
            
            return df
            
        except Exception as e:
            print(f"❌ Error loading data: {e}")
            return None
    
    def create_health_labels(self, df):
        """Create comprehensive health status labels based on system and security metrics"""
        print("🏥 Creating health diagnosis labels...")
        
        health_labels = []
        overall_scores = []
        
        for idx, row in df.iterrows():
            # Start with perfect health
            performance_score = 100
            security_score = row.get('security_score', 85)
            
            # Performance-based scoring
            # Disk space (critical factor)
            if row['disk_percent'] >= 95:
                performance_score -= 40
            elif row['disk_percent'] >= 90:
                performance_score -= 25
            elif row['disk_percent'] >= 85:
                performance_score -= 10
            
            # Memory usage
            if row['memory_percent'] >= 90:
                performance_score -= 20
            elif row['memory_percent'] >= 80:
                performance_score -= 15
            elif row['memory_percent'] >= 70:
                performance_score -= 5
            
            # CPU usage
            if row['cpu_percent'] >= 90:
                performance_score -= 15
            elif row['cpu_percent'] >= 80:
                performance_score -= 10
            elif row['cpu_percent'] >= 70:
                performance_score -= 5
            
            # Temperature impact
            if row['temperature'] > 80:
                performance_score -= 15
            elif row['temperature'] > 70:
                performance_score -= 8
            elif row['temperature'] > 60:
                performance_score -= 3
            
            # Security-based adjustments
            if not row.get('antivirus_enabled', True):
                security_score -= 30
            
            if not row.get('real_time_protection', True):
                security_score -= 20
            
            # Old virus definitions
            def_age = row.get('definition_age_days', 0)
            if def_age > 30:
                security_score -= 25
            elif def_age > 7:
                security_score -= 10
            
            # Threats and vulnerabilities
            security_score -= row.get('suspicious_activity_count', 0) * 10
            security_score -= row.get('vulnerability_count', 0) * 5
            
            # Memory leak detection (if we have previous data)
            if idx > 0 and df.iloc[idx]['computer_name'] == df.iloc[idx-1]['computer_name']:
                prev_memory = df.iloc[idx-1]['memory_percent']
                memory_increase = row['memory_percent'] - prev_memory
                if memory_increase > 10:  # 10% increase in one reading
                    performance_score -= 15
            
            # Combine performance and security scores
            overall_score = (performance_score * 0.6) + (security_score * 0.4)
            overall_score = max(0, min(100, overall_score))  # Clamp between 0-100
            
            # Determine health category
            if overall_score >= 90:
                health_label = "Excellent"
            elif overall_score >= 75:
                health_label = "Good"
            elif overall_score >= 60:
                health_label = "Fair"
            elif overall_score >= 40:
                health_label = "Poor"
            else:
                health_label = "Critical"
            
            health_labels.append(health_label)
            overall_scores.append(overall_score)
        
        df['health_label'] = health_labels
        df['overall_health_score'] = overall_scores
        
        # Create security-specific labels
        security_labels = []
        for score in df['security_score']:
            if score >= 90:
                security_labels.append("Secure")
            elif score >= 70:
                security_labels.append("Protected")
            elif score >= 50:
                security_labels.append("Vulnerable")
            else:
                security_labels.append("At Risk")
        
        df['security_label'] = security_labels
        
        # Print distributions
        print("📋 Health label distribution:")
        print(df['health_label'].value_counts())
        print("\n🛡️ Security label distribution:")
        print(df['security_label'].value_counts())
        print(f"\n💻 Computers analyzed: {df['computer_name'].nunique()}")
        
        return df
    
    def create_features(self, df):
        """Create additional features for better prediction"""
        print("🔧 Engineering features...")
        
        # Encode categorical variables
        df['computer_encoded'] = self.computer_encoder.fit_transform(df['computer_name'])
        df['os_encoded'] = self.os_encoder.fit_transform(df['os_system'])
        
        # Rolling averages for trend analysis
        df_features = df.copy()
        
        for computer in df['computer_name'].unique():
            mask = df['computer_name'] == computer
            computer_data = df[mask].copy()
            
            # Calculate rolling averages (5-point window)
            window = min(5, len(computer_data))
            if window > 1:
                computer_data['cpu_trend'] = computer_data['cpu_percent'].rolling(window=window, min_periods=1).mean()
                computer_data['memory_trend'] = computer_data['memory_percent'].rolling(window=window, min_periods=1).mean()
                computer_data['security_trend'] = computer_data['security_score'].rolling(window=window, min_periods=1).mean()
            else:
                computer_data['cpu_trend'] = computer_data['cpu_percent']
                computer_data['memory_trend'] = computer_data['memory_percent']
                computer_data['security_trend'] = computer_data['security_score']
            
            # Rate of change
            computer_data['memory_change_rate'] = computer_data['memory_percent'].diff().fillna(0)
            computer_data['cpu_change_rate'] = computer_data['cpu_percent'].diff().fillna(0)
            computer_data['security_change_rate'] = computer_data['security_score'].diff().fillna(0)
            
            # Update the main dataframe
            df_features.loc[mask, ['cpu_trend', 'memory_trend', 'security_trend', 
                                 'memory_change_rate', 'cpu_change_rate', 'security_change_rate']] = \
                computer_data[['cpu_trend', 'memory_trend', 'security_trend', 
                             'memory_change_rate', 'cpu_change_rate', 'security_change_rate']]
        
        # Resource ratios and derived features
        df_features['memory_to_cpu_ratio'] = df_features['memory_percent'] / (df_features['cpu_percent'] + 1)
        df_features['disk_danger_score'] = np.where(df_features['disk_percent'] > 85, 
                                                   df_features['disk_percent'] - 85, 0)
        
        # Network activity level
        df_features['total_network_mb'] = df_features['network_sent_mb'] + df_features['network_recv_mb']
        df_features['network_ratio'] = df_features['network_recv_mb'] / (df_features['network_sent_mb'] + 1)
        
        # Security risk factors
        df_features['security_risk_score'] = (
            (~df_features['antivirus_enabled']).astype(int) * 30 +
            (~df_features['real_time_protection']).astype(int) * 20 +
            df_features['definition_age_days'] * 0.5 +
            df_features['suspicious_activity_count'] * 10 +
            df_features['vulnerability_count'] * 5
        )
        
        # Time-based features
        df_features['hour'] = df_features['timestamp'].dt.hour
        df_features['day_of_week'] = df_features['timestamp'].dt.dayofweek
        
        # Hardware performance indicators
        df_features['memory_pressure'] = df_features['memory_used_gb'] / df_features['memory_total_gb']
        df_features['disk_efficiency'] = df_features['disk_free_gb'] / df_features['disk_total_gb']
        
        # Update feature columns to include new features
        additional_features = [
            'computer_encoded', 'os_encoded', 'cpu_trend', 'memory_trend', 'security_trend',
            'memory_change_rate', 'cpu_change_rate', 'security_change_rate',
            'memory_to_cpu_ratio', 'disk_danger_score', 'total_network_mb', 'network_ratio',
            'security_risk_score', 'hour', 'day_of_week', 'memory_pressure', 'disk_efficiency'
        ]
        
        # Only add features that exist in the dataframe
        for feature in additional_features:
            if feature in df_features.columns and feature not in self.feature_columns:
                self.feature_columns.append(feature)
        
        return df_features
    
    def train_models(self, df):
        """Train AI models for comprehensive health and security prediction"""
        print("🤖 Training AI models...")
        
        # Prepare features (only use existing columns)
        available_features = [col for col in self.feature_columns if col in df.columns]
        X = df[available_features].fillna(0)
        
        print(f"📊 Using {len(available_features)} features for training")
        
        # Target variables
        y_health = df['health_label']
        y_security = df['security_label']
        y_health_score = df['overall_health_score']
        y_security_score = df['security_score']
        
        # Split data
        X_train, X_test, y_health_train, y_health_test, y_sec_train, y_sec_test, \
        y_hscore_train, y_hscore_test, y_sscore_train, y_sscore_test = train_test_split(
            X, y_health, y_security, y_health_score, y_security_score, 
            test_size=0.2, random_state=42, stratify=y_health
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train health classifier
        print("🏥 Training health classifier...")
        self.health_classifier = RandomForestClassifier(
            n_estimators=100, 
            random_state=42,
            class_weight='balanced'
        )
        self.health_classifier.fit(X_train_scaled, y_health_train)
        
        # Train security classifier
        print("🛡️ Training security classifier...")
        self.security_classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            class_weight='balanced'
        )
        self.security_classifier.fit(X_train_scaled, y_sec_train)
        
        # Train health score predictor
        print("📈 Training health score predictor...")
        self.performance_predictor = GradientBoostingRegressor(
            n_estimators=100,
            random_state=42
        )
        self.performance_predictor.fit(X_train_scaled, y_hscore_train)
        
        # Train security score predictor
        print("🔒 Training security score predictor...")
        self.security_predictor = GradientBoostingRegressor(
            n_estimators=100,
            random_state=42
        )
        self.security_predictor.fit(X_train_scaled, y_sscore_train)
        
        # Evaluate models
        print("\n📊 Model Evaluation:")
        print("="*60)
        
        # Health classifier evaluation
        health_pred = self.health_classifier.predict(X_test_scaled)
        print("🏥 Health Classification Report:")
        print(classification_report(y_health_test, health_pred))
        
        # Security classifier evaluation
        security_pred = self.security_classifier.predict(X_test_scaled)
        print("\n🛡️ Security Classification Report:")
        print(classification_report(y_sec_test, security_pred))
        
        # Score predictors evaluation
        health_score_pred = self.performance_predictor.predict(X_test_scaled)
        security_score_pred = self.security_predictor.predict(X_test_scaled)
        
        health_mse = mean_squared_error(y_hscore_test, health_score_pred)
        security_mse = mean_squared_error(y_sscore_test, security_score_pred)
        
        print(f"\n📊 Health Score Prediction MSE: {health_mse:.2f}")
        print(f"🔒 Security Score Prediction MSE: {security_mse:.2f}")
        
        # Feature importance
        self.print_feature_importance()
        
        return X_test_scaled, y_health_test, y_sec_test
    
    def print_feature_importance(self):
        """Print which features are most important for predictions"""
        print("\n🔍 Most Important Features:")
        print("="*50)
        
        # Get feature importance from health classifier
        available_features = [col for col in self.feature_columns if col in self.health_classifier.feature_names_in_]
        importances = self.health_classifier.feature_importances_
        
        feature_importance = pd.DataFrame({
            'feature': available_features,
            'importance': importances
        }).sort_values('importance', ascending=False)
        
        print("Top 10 features for health diagnosis:")
        for idx, row in feature_importance.head(10).iterrows():
            print(f"  {row['feature']}: {row['importance']:.3f}")
    
    def diagnose_computer(self, system_data):
        """Comprehensive diagnosis of a computer's health and security"""
        if self.health_classifier is None:
            print("❌ Models not trained yet!")
            return None
        
        # Prepare data
        data_dict = {}
        available_features = [col for col in self.feature_columns if col in self.health_classifier.feature_names_in_]
        
        for col in available_features:
            if col in system_data:
                data_dict[col] = system_data[col]
            elif col == 'computer_encoded':
                # Handle unknown computer names
                try:
                    data_dict[col] = self.computer_encoder.transform([system_data.get('computer_name', 'Unknown')])[0]
                except:
                    data_dict[col] = 0
            elif col == 'os_encoded':
                # Handle unknown OS
                try:
                    data_dict[col] = self.os_encoder.transform([system_data.get('os_system', 'Unknown')])[0]
                except:
                    data_dict[col] = 0
            else:
                data_dict[col] = 0  # Default value for missing features
        
        X = pd.DataFrame([data_dict])
        X_scaled = self.scaler.transform(X)
        
        # Predictions
        health_pred = self.health_classifier.predict(X_scaled)[0]
        health_prob = self.health_classifier.predict_proba(X_scaled)[0]
        
        security_pred = self.security_classifier.predict(X_scaled)[0]
        security_prob = self.security_classifier.predict_proba(X_scaled)[0]
        
        health_score = self.performance_predictor.predict(X_scaled)[0]
        security_score = self.security_predictor.predict(X_scaled)[0]
        
        # Get class probabilities
        health_classes = self.health_classifier.classes_
        security_classes = self.security_classifier.classes_
        
        health_prob_dict = dict(zip(health_classes, health_prob))
        security_prob_dict = dict(zip(security_classes, security_prob))
        
        return {
            'health_status': health_pred,
            'health_confidence': max(health_prob),
            'health_score': max(0, min(100, health_score)),
            'health_probabilities': health_prob_dict,
            'security_status': security_pred,
            'security_confidence': max(security_prob),
            'security_score': max(0, min(100, security_score)),
            'security_probabilities': security_prob_dict
        }
    
    def generate_comprehensive_recommendations(self, system_data, diagnosis):
        """Generate detailed recommendations based on diagnosis"""
        recommendations = []
        
        # Critical issues first
        if system_data.get('disk_percent', 0) >= 95:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Storage',
                'issue': 'Disk space critically low',
                'action': 'Delete unnecessary files immediately. Move large files to external storage.',
                'impact': 'System may become unstable or crash',
                'urgency': 'Immediate'
            })
        
        # Security issues
        if not system_data.get('antivirus_enabled', True):
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Security',
                'issue': 'Antivirus protection disabled',
                'action': 'Enable Windows Defender or install antivirus software immediately.',
                'impact': 'Computer vulnerable to malware attacks',
                'urgency': 'Immediate'
            })
        
        if not system_data.get('real_time_protection', True):
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Security',
                'issue': 'Real-time protection disabled',
                'action': 'Enable real-time protection in Windows Security settings.',
                'impact': 'Reduced protection against live threats',
                'urgency': 'Within 24 hours'
            })
        
        # Definition age check
        def_age = system_data.get('definition_age_days', 0)
        if def_age > 7:
            priority = 'HIGH' if def_age > 30 else 'MEDIUM'
            recommendations.append({
                'priority': priority,
                'category': 'Security',
                'issue': f'Virus definitions {def_age} days old',
                'action': 'Update virus definitions and run a full system scan.',
                'impact': 'Reduced protection against new threats',
                'urgency': 'Within 48 hours'
            })
        
        # Performance issues
        if system_data.get('memory_percent', 0) >= 85:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Performance',
                'issue': 'High memory usage',
                'action': 'Close unnecessary applications, restart computer, or add more RAM.',
                'impact': 'System slowdown and potential crashes',
                'urgency': 'Within 24 hours'
            })
        
        if system_data.get('cpu_percent', 0) >= 80:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Performance',
                'issue': 'High CPU usage',
                'action': 'Check Task Manager for resource-heavy processes and close unnecessary ones.',
                'impact': 'Reduced system responsiveness',
                'urgency': 'Monitor closely'
            })
        
        # Temperature warnings
        if system_data.get('temperature', 0) > 80:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Hardware',
                'issue': f'High system temperature ({system_data["temperature"]}°C)',
                'action': 'Clean dust from fans, check ventilation, consider thermal paste replacement.',
                'impact': 'Potential hardware damage and performance throttling',
                'urgency': 'Within 48 hours'
            })
        
        # Security threats
        threat_count = system_data.get('suspicious_activity_count', 0)
        if threat_count > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Security',
                'issue': f'{threat_count} suspicious activities detected',
                'action': 'Run full antivirus scan, check for malware, monitor system behavior.',
                'impact': 'Potential data theft or system compromise',
                'urgency': 'Within 24 hours'
            })
        
        # Vulnerabilities
        vuln_count = system_data.get('vulnerability_count', 0)
        if vuln_count > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Security',
                'issue': f'{vuln_count} security vulnerabilities found',
                'action': 'Install pending Windows updates, update software, review security settings.',
                'impact': 'Increased risk of security breaches',
                'urgency': 'Within 1 week'
            })
        
        return recommendations
    
    def save_models(self, model_path="security_enhanced_ai_models"):
        """Save trained models"""
        print(f"💾 Saving models to {model_path}...")
        joblib.dump({
            'health_classifier': self.health_classifier,
            'security_classifier': self.security_classifier,
            'performance_predictor': self.performance_predictor,
            'security_predictor': self.security_predictor,
            'scaler': self.scaler,
            'computer_encoder': self.computer_encoder,
            'os_encoder': self.os_encoder,
            'feature_columns': self.feature_columns
        }, f"{model_path}.pkl")
        print("✅ Models saved successfully!")
    
    def load_models(self, model_path="security_enhanced_ai_models"):
        """Load pre-trained models"""
        try:
            print(f"📂 Loading models from {model_path}...")
            models = joblib.load(f"{model_path}.pkl")
            self.health_classifier = models['health_classifier']
            self.security_classifier = models['security_classifier']
            self.performance_predictor = models['performance_predictor']
            self.security_predictor = models['security_predictor']
            self.scaler = models['scaler']
            self.computer_encoder = models['computer_encoder']
            self.os_encoder = models['os_encoder']
            self.feature_columns = models['feature_columns']
            print("✅ Models loaded successfully!")
            return True
        except Exception as e:
            print(f"❌ Error loading models: {e}")
            return False

class SecurityEnhancedComputerDoctorAI:
    """User-friendly interface for comprehensive computer health and security diagnosis"""
    
    def __init__(self):
        self.ai = SecurityEnhancedComputerHealthAI()
        
    def train_from_security_data(self, csv_file_path="data/system_security_all_computers.csv"):
        """Train the AI from security-enhanced monitoring data"""
        print("🎓 Starting Security-Enhanced AI Training Process...")
        print("="*70)
        
        # Load data
        df = self.ai.load_security_data(csv_file_path)
        if df is None:
            return False
        
        if len(df) < 50:
            print(f"⚠️  Warning: Only {len(df)} data points available.")
            print("   For better AI performance, collect at least 500+ data points")
            print("   Current data will work but may have limited accuracy")
        
        # Create health labels
        df = self.ai.create_health_labels(df)
        
        # Engineer features
        df = self.ai.create_features(df)
        
        # Train models
        self.ai.train_models(df)
        
        # Save models
        self.ai.save_models()
        
        print("\n🎉 Security-Enhanced AI Training Complete!")
        print("Your computer health and security AI is ready to diagnose problems!")
        
        return True
    
    def diagnose_current_system(self, current_data):
        """Comprehensive diagnosis of current system state"""
        print("\n🔍 Analyzing your computer's health and security...")
        print("="*55)
        
        # Get diagnosis
        diagnosis = self.ai.diagnose_computer(current_data)
        if diagnosis is None:
            return
        
        # Display results
        health_status = diagnosis['health_status']
        health_confidence = diagnosis['health_confidence'] * 100
        health_score = diagnosis['health_score']
        
        security_status = diagnosis['security_status']
        security_confidence = diagnosis['security_confidence'] * 100
        security_score = diagnosis['security_score']
        
        # Health status emoji
        health_emojis = {
            'Excellent': '💚', 'Good': '💛', 'Fair': '🧡', 
            'Poor': '❤️', 'Critical': '🚨'
        }
        security_emojis = {
            'Secure': '🛡️', 'Protected': '🟢', 'Vulnerable': '🟡', 'At Risk': '🔴'
        }
        
        health_emoji = health_emojis.get(health_status, '❓')
        security_emoji = security_emojis.get(security_status, '❓')
        
        print(f"{health_emoji} Overall Health: {health_status}")
        print(f"🎯 Health Confidence: {health_confidence:.1f}%")
        print(f"📊 Health Score: {health_score:.1f}/100")
        print()
        print(f"{security_emoji} Security Status: {security_status}")
        print(f"🎯 Security Confidence: {security_confidence:.1f}%")
        print(f"🔒 Security Score: {security_score:.1f}/100")
        
        # Show probability breakdowns
        print(f"\n📈 Health Analysis Breakdown:")
        for status, prob in diagnosis['health_probabilities'].items():
            print(f"  {status}: {prob*100:.1f}%")
        
        print(f"\n🛡️ Security Analysis Breakdown:")
        for status, prob in diagnosis['security_probabilities'].items():
            print(f"  {status}: {prob*100:.1f}%")
        
        # Generate recommendations
        recommendations = self.ai.generate_comprehensive_recommendations(current_data, diagnosis)
        
        if recommendations:
            print(f"\n💡 Personalized Recommendations:")
            for i, rec in enumerate(recommendations, 1):
                priority_emojis = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '⚡', 'LOW': 'ℹ️'}
                emoji = priority_emojis.get(rec['priority'], 'ℹ️')
                
                print(f"\n{i}. {emoji} {rec['priority']} - {rec['category']}")
                print(f"   Issue: {rec['issue']}")
                print(f"   Action: {rec['action']}")
                print(f"   Impact: {rec['impact']}")
                print(f"   Timeline: {rec['urgency']}")
        else:
            print(f"\n✅ Excellent! No critical issues detected.")
            print("   Your computer is running optimally.")
        
        return diagnosis

def main():
    """Main function to run the Security-Enhanced Computer Health AI system"""
    print("🖥️  Security-Enhanced Computer Health AI System")
    print("=" * 60)
    print("🏥 Advanced AI-powered computer health and security diagnosis")
    print("🛡️ Real-time threat detection and system optimization")
    print("=" * 60)
    
    # Initialize the AI doctor
    doctor = SecurityEnhancedComputerDoctorAI()
    
    while True:
        print("\n🔧 What would you like to do?")
        print("1. 🎓 Train AI from security monitoring data")
        print("2. 🔍 Diagnose current computer health & security")
        print("3. 📊 Load pre-trained models")
        print("4. 🏥 Diagnose with sample data")
        print("5. 📈 Generate health report from CSV")
        print("6. ❌ Exit")
        
        try:
            choice = input("\n👉 Enter your choice (1-6): ").strip()
            
            if choice == '1':
                print("\n🎓 Training AI from Security Data")
                print("-" * 40)
                
                # Check for default data file
                default_file = "data/system_security_all_computers.csv"
                custom_file = input(f"📁 Enter CSV file path (or press Enter for '{default_file}'): ").strip()
                
                if not custom_file:
                    csv_file = default_file
                else:
                    csv_file = custom_file
                
                success = doctor.train_from_security_data(csv_file)
                
                if success:
                    print("\n🎉 AI training completed successfully!")
                    print("✅ Your computer health AI is now ready for diagnosis!")
                else:
                    print("\n❌ Training failed. Please check your data file.")
                    
            elif choice == '2':
                print("\n🔍 Computer Health & Security Diagnosis")
                print("-" * 45)
                
                # Check if models are loaded
                if doctor.ai.health_classifier is None:
                    print("⚠️  No trained models found!")
                    load_choice = input("Would you like to load pre-trained models? (y/n): ").lower()
                    if load_choice == 'y':
                        if not doctor.ai.load_models():
                            print("❌ Failed to load models. Please train the AI first.")
                            continue
                    else:
                        print("Please train the AI first (option 1) or load models (option 3).")
                        continue
                
                # Get current system data
                print("\n📋 Please enter your current system information:")
                try:
                    current_data = {
                        'computer_name': input("💻 Computer name: ").strip() or "MyComputer",
                        'os_system': input("🖥️  Operating System (Windows/Linux/macOS): ").strip() or "Windows",
                        'cpu_percent': float(input("⚡ CPU usage percentage (0-100): ") or "25"),
                        'memory_percent': float(input("🧠 Memory usage percentage (0-100): ") or "45"),
                        'memory_used_gb': float(input("💾 Memory used (GB): ") or "8"),
                        'memory_total_gb': float(input("📊 Total memory (GB): ") or "16"),
                        'disk_percent': float(input("💽 Disk usage percentage (0-100): ") or "60"),
                        'disk_free_gb': float(input("💿 Free disk space (GB): ") or "200"),
                        'disk_total_gb': float(input("🗄️  Total disk space (GB): ") or "500"),
                        'process_count': int(input("⚙️  Number of running processes: ") or "150"),
                        'temperature': float(input("🌡️  System temperature (°C): ") or "45"),
                        'uptime_hours': float(input("⏰ System uptime (hours): ") or "24"),
                        'network_sent_mb': float(input("📤 Network data sent (MB): ") or "100"),
                        'network_recv_mb': float(input("📥 Network data received (MB): ") or "500"),
                    }
                    
                    # Security-specific data
                    print("\n🛡️ Security Information:")
                    antivirus_input = input("🦠 Antivirus enabled? (y/n): ").lower()
                    current_data['antivirus_enabled'] = antivirus_input in ['y', 'yes', '1', 'true']
                    
                    protection_input = input("🛡️ Real-time protection active? (y/n): ").lower()
                    current_data['real_time_protection'] = protection_input in ['y', 'yes', '1', 'true']
                    
                    current_data['definition_age_days'] = float(input("📅 Virus definition age (days): ") or "1")
                    current_data['suspicious_activity_count'] = int(input("🔍 Suspicious activities detected: ") or "0")
                    current_data['vulnerability_count'] = int(input("🚨 Known vulnerabilities: ") or "0")
                    current_data['security_software_count'] = int(input("🔐 Security software installed: ") or "1")
                    
                    # Perform diagnosis
                    diagnosis = doctor.diagnose_current_system(current_data)
                    
                except ValueError:
                    print("❌ Invalid input. Please enter numeric values where required.")
                except KeyboardInterrupt:
                    print("\n⚠️  Diagnosis cancelled by user.")
                    
            elif choice == '3':
                print("\n📂 Loading Pre-trained Models")
                print("-" * 35)
                
                model_path = input("📁 Enter model file path (or press Enter for default): ").strip()
                if not model_path:
                    model_path = "security_enhanced_ai_models"
                
                if doctor.ai.load_models(model_path):
                    print("✅ Models loaded successfully!")
                    print("🎯 AI is ready for computer diagnosis!")
                else:
                    print("❌ Failed to load models. Please check the file path.")
                    
            elif choice == '4':
                print("\n🏥 Sample Computer Diagnosis")
                print("-" * 35)
                
                # Check if models are loaded
                if doctor.ai.health_classifier is None:
                    print("⚠️  Loading default models...")
                    if not doctor.ai.load_models():
                        print("❌ No trained models available. Please train the AI first.")
                        continue
                
                # Create sample data scenarios
                scenarios = {
                    "healthy": {
                        'computer_name': 'HealthyPC',
                        'os_system': 'Windows',
                        'cpu_percent': 15.0,
                        'memory_percent': 35.0,
                        'memory_used_gb': 5.6,
                        'memory_total_gb': 16.0,
                        'disk_percent': 45.0,
                        'disk_free_gb': 275.0,
                        'disk_total_gb': 500.0,
                        'process_count': 120,
                        'temperature': 42.0,
                        'uptime_hours': 8.0,
                        'network_sent_mb': 50.0,
                        'network_recv_mb': 200.0,
                        'antivirus_enabled': True,
                        'real_time_protection': True,
                        'definition_age_days': 1.0,
                        'suspicious_activity_count': 0,
                        'vulnerability_count': 0,
                        'security_software_count': 2
                    },
                    "problematic": {
                        'computer_name': 'ProblematicPC',
                        'os_system': 'Windows',
                        'cpu_percent': 85.0,
                        'memory_percent': 92.0,
                        'memory_used_gb': 14.7,
                        'memory_total_gb': 16.0,
                        'disk_percent': 96.0,
                        'disk_free_gb': 20.0,
                        'disk_total_gb': 500.0,
                        'process_count': 250,
                        'temperature': 78.0,
                        'uptime_hours': 168.0,
                        'network_sent_mb': 1000.0,
                        'network_recv_mb': 5000.0,
                        'antivirus_enabled': False,
                        'real_time_protection': False,
                        'definition_age_days': 45.0,
                        'suspicious_activity_count': 3,
                        'vulnerability_count': 7,
                        'security_software_count': 0
                    },
                    "moderate": {
                        'computer_name': 'ModeratePC',
                        'os_system': 'Windows',
                        'cpu_percent': 55.0,
                        'memory_percent': 68.0,
                        'memory_used_gb': 10.9,
                        'memory_total_gb': 16.0,
                        'disk_percent': 78.0,
                        'disk_free_gb': 110.0,
                        'disk_total_gb': 500.0,
                        'process_count': 180,
                        'temperature': 62.0,
                        'uptime_hours': 72.0,
                        'network_sent_mb': 300.0,
                        'network_recv_mb': 1200.0,
                        'antivirus_enabled': True,
                        'real_time_protection': True,
                        'definition_age_days': 12.0,
                        'suspicious_activity_count': 1,
                        'vulnerability_count': 2,
                        'security_software_count': 1
                    }
                }
                
                print("🎭 Available sample scenarios:")
                print("1. 💚 Healthy computer")
                print("2. 🚨 Problematic computer") 
                print("3. 🧡 Moderate issues computer")
                
                scenario_choice = input("\n👉 Choose scenario (1-3): ").strip()
                scenario_map = {'1': 'healthy', '2': 'problematic', '3': 'moderate'}
                
                if scenario_choice in scenario_map:
                    selected_scenario = scenario_map[scenario_choice]
                    sample_data = scenarios[selected_scenario]
                    
                    print(f"\n🔍 Analyzing {selected_scenario} computer scenario...")
                    diagnosis = doctor.diagnose_current_system(sample_data)
                else:
                    print("❌ Invalid scenario choice.")
                    
            elif choice == '5':
                print("\n📈 Generate Health Report from CSV")
                print("-" * 40)
                
                if doctor.ai.health_classifier is None:
                    print("⚠️  Loading models...")
                    if not doctor.ai.load_models():
                        print("❌ No trained models available. Please train the AI first.")
                        continue
                
                csv_file = input("📁 Enter CSV file path for analysis: ").strip()
                if not csv_file:
                    print("❌ No file path provided.")
                    continue
                
                try:
                    # Load and analyze the CSV file
                    df = doctor.ai.load_security_data(csv_file)
                    if df is not None:
                        df = doctor.ai.create_health_labels(df)
                        
                        print(f"\n📊 Health Report for {csv_file}")
                        print("=" * 50)
                        print(f"📅 Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                        print(f"💻 Computers Analyzed: {df['computer_name'].nunique()}")
                        print(f"📈 Total Data Points: {len(df)}")
                        
                        print(f"\n🏥 Overall Health Distribution:")
                        health_dist = df['health_label'].value_counts()
                        for status, count in health_dist.items():
                            percentage = (count / len(df)) * 100
                            print(f"  {status}: {count} ({percentage:.1f}%)")
                        
                        print(f"\n🛡️ Security Status Distribution:")
                        security_dist = df['security_label'].value_counts()
                        for status, count in security_dist.items():
                            percentage = (count / len(df)) * 100
                            print(f"  {status}: {count} ({percentage:.1f}%)")
                        
                        print(f"\n📊 Average Scores:")
                        print(f"  Health Score: {df['overall_health_score'].mean():.1f}/100")
                        print(f"  Security Score: {df['security_score'].mean():.1f}/100")
                        
                        # Computer-specific summary
                        print(f"\n💻 Per-Computer Summary:")
                        for computer in df['computer_name'].unique():
                            comp_data = df[df['computer_name'] == computer]
                            latest_health = comp_data.iloc[-1]['health_label']
                            latest_security = comp_data.iloc[-1]['security_label']
                            avg_health_score = comp_data['overall_health_score'].mean()
                            avg_security_score = comp_data['security_score'].mean()
                            
                            print(f"  {computer}: {latest_health} health, {latest_security} security")
                            print(f"    Avg Health: {avg_health_score:.1f}, Avg Security: {avg_security_score:.1f}")
                        
                except Exception as e:
                    print(f"❌ Error analyzing CSV file: {e}")
                    
            elif choice == '6':
                print("\n👋 Thank you for using Security-Enhanced Computer Health AI!")
                print("🏥 Keep your computers healthy and secure!")
                break
                
            else:
                print("❌ Invalid choice. Please enter 1-6.")
                
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye! Take care of your computer's health!")
            break
        except Exception as e:
            print(f"❌ An error occurred: {e}")
            print("Please try again or restart the program.")

if __name__ == "__main__":
    main()