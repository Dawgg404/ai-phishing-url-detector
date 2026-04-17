"""
Machine Learning model for phishing detection
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import pickle
import os
import warnings

warnings.filterwarnings('ignore')


class PhishingMLModel:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = [
            'url_length', 'domain_length', 'path_length', 'query_length',
            'fragment_length', 'subdomain_count', 'path_depth',
            'special_char_count', 'digit_count', 'letter_count',
            'uppercase_count', 'has_ip', 'has_port', 'is_https',
            'suspicious_tld', 'url_entropy'
        ]
        self._trained = False
    
    def create_synthetic_dataset(self, n_samples=1000):
        """
        Create a synthetic dataset for training when real dataset is not available
        """
        np.random.seed(42)
        
        # Generate legitimate URLs features (typically shorter, fewer special chars)
        legitimate_samples = n_samples // 2
        legit_data = {
            'url_length': np.random.normal(40, 15, legitimate_samples).clip(10, 200),
            'domain_length': np.random.normal(12, 5, legitimate_samples).clip(3, 50),
            'path_length': np.random.normal(10, 8, legitimate_samples).clip(0, 100),
            'query_length': np.random.exponential(5, legitimate_samples).clip(0, 200),
            'fragment_length': np.random.exponential(2, legitimate_samples).clip(0, 50),
            'subdomain_count': np.random.poisson(1, legitimate_samples).clip(0, 5),
            'path_depth': np.random.poisson(2, legitimate_samples).clip(0, 10),
            'special_char_count': np.random.poisson(3, legitimate_samples).clip(0, 20),
            'digit_count': np.random.poisson(5, legitimate_samples).clip(0, 30),
            'letter_count': np.random.normal(25, 10, legitimate_samples).clip(5, 150),
            'uppercase_count': np.random.poisson(8, legitimate_samples).clip(0, 50),
            'has_ip': np.random.choice([0, 1], legitimate_samples, p=[0.95, 0.05]),
            'has_port': np.random.choice([0, 1], legitimate_samples, p=[0.9, 0.1]),
            'is_https': np.random.choice([0, 1], legitimate_samples, p=[0.3, 0.7]),
            'suspicious_tld': np.random.choice([0, 1], legitimate_samples, p=[0.9, 0.1]),
            'url_entropy': np.random.normal(4.2, 0.5, legitimate_samples).clip(2, 6),
            'is_phishing': np.zeros(legitimate_samples)
        }
        
        # Generate phishing URLs features (typically longer, more special chars, suspicious patterns)
        phishing_samples = n_samples - legitimate_samples
        phishing_data = {
            'url_length': np.random.normal(80, 25, phishing_samples).clip(30, 300),
            'domain_length': np.random.normal(25, 15, phishing_samples).clip(10, 100),
            'path_length': np.random.normal(25, 15, phishing_samples).clip(5, 150),
            'query_length': np.random.exponential(15, phishing_samples).clip(0, 300),
            'fragment_length': np.random.exponential(3, phishing_samples).clip(0, 100),
            'subdomain_count': np.random.poisson(3, phishing_samples).clip(1, 8),
            'path_depth': np.random.poisson(4, phishing_samples).clip(1, 15),
            'special_char_count': np.random.poisson(10, phishing_samples).clip(3, 50),
            'digit_count': np.random.poisson(15, phishing_samples).clip(2, 60),
            'letter_count': np.random.normal(45, 20, phishing_samples).clip(10, 200),
            'uppercase_count': np.random.poisson(15, phishing_samples).clip(2, 80),
            'has_ip': np.random.choice([0, 1], phishing_samples, p=[0.7, 0.3]),
            'has_port': np.random.choice([0, 1], phishing_samples, p=[0.8, 0.2]),
            'is_https': np.random.choice([0, 1], phishing_samples, p=[0.6, 0.4]),
            'suspicious_tld': np.random.choice([0, 1], phishing_samples, p=[0.4, 0.6]),
            'url_entropy': np.random.normal(5.2, 0.8, phishing_samples).clip(3, 8),
            'is_phishing': np.ones(phishing_samples)
        }
        
        # Combine datasets
        data = {}
        for feature in self.feature_names + ['is_phishing']:
            data[feature] = np.concatenate([legit_data[feature], phishing_data[feature]])
        
        df = pd.DataFrame(data)
        
        # Shuffle the dataset
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        return df
    
    def load_or_create_dataset(self):
        """
        Load dataset from file or create synthetic one
        """
        dataset_path = "data/phishing_dataset.csv"
        
        if os.path.exists(dataset_path):
            try:
                df = pd.read_csv(dataset_path)
                print(f"Loaded dataset with {len(df)} samples from {dataset_path}")
                return df
            except Exception as e:
                print(f"Error loading dataset: {e}, creating synthetic data")
        
        # Create synthetic dataset
        df = self.create_synthetic_dataset()
        print(f"Created synthetic dataset with {len(df)} samples")
        
        # Save for future use
        os.makedirs("data", exist_ok=True)
        df.to_csv(dataset_path, index=False)
        print(f"Saved dataset to {dataset_path}")
        
        return df
    
    def train_model(self):
        """
        Train the machine learning model
        """
        try:
            # Load dataset
            df = self.load_or_create_dataset()
            
            # Prepare features and target
            X = df[self.feature_names]
            y = df['is_phishing']
            
            # Handle missing values
            X = X.fillna(0)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train model
            self.model = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2
            )
            
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            train_score = self.model.score(X_train_scaled, y_train)
            test_score = self.model.score(X_test_scaled, y_test)
            
            print(f"Model trained successfully!")
            print(f"Training accuracy: {train_score:.3f}")
            print(f"Test accuracy: {test_score:.3f}")
            
            # Save model
            self.save_model()
            self._trained = True
            
            return True
            
        except Exception as e:
            print(f"Error training model: {e}")
            return False
    
    def predict_single(self, features):
        """
        Predict phishing probability for a single URL
        
        Args:
            features (dict): Dictionary of extracted features
            
        Returns:
            float: Probability of being phishing (0-1)
        """
        if not self.is_trained():
            raise ValueError("Model not trained")
        
        # Prepare feature vector
        feature_vector = []
        for feature_name in self.feature_names:
            value = features.get(feature_name, 0)
            feature_vector.append(float(value) if value is not None else 0.0)
        
        # Scale features
        feature_vector = np.array(feature_vector).reshape(1, -1)
        if self.scaler:
            feature_vector = self.scaler.transform(feature_vector)
        
        # Predict probability
        probability = self.model.predict_proba(feature_vector)[0][1]  # Probability of class 1 (phishing)
        
        return probability
    
    def predict_batch(self, features_list):
        """
        Predict phishing probability for multiple URLs
        
        Args:
            features_list (list): List of feature dictionaries
            
        Returns:
            list: List of probabilities
        """
        if not self.is_trained():
            raise ValueError("Model not trained")
        
        predictions = []
        for features in features_list:
            try:
                prob = self.predict_single(features)
                predictions.append(prob)
            except Exception as e:
                print(f"Error predicting: {e}")
                predictions.append(0.0)
        
        return predictions
    
    def is_trained(self):
        """Check if model is trained"""
        return self._trained and self.model is not None
    
    def save_model(self, filepath="models/phishing_model.pkl"):
        """Save trained model to file"""
        try:
            os.makedirs("models", exist_ok=True)
            
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
            
            print(f"Model saved to {filepath}")
            
        except Exception as e:
            print(f"Error saving model: {e}")
    
    def load_model(self, filepath="models/phishing_model.pkl"):
        """Load trained model from file"""
        try:
            if not os.path.exists(filepath):
                return False
            
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            self._trained = True
            
            print(f"Model loaded from {filepath}")
            return True
            
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
