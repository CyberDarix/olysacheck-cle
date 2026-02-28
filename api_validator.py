#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                 OLYSACHECK - VALIDATEUR D'API PROFESSIONNEL                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Version: 3.0.0 - AVEC VALIDATION PAYPAL SÉCURISÉE                          ║
║  Auteur: OlysaCheck Security Team                                           ║
║  Description: Service de validation des clés API avec paiement PayPal       ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import json
import time
import hashlib
import hmac
import sqlite3
import logging
import ipaddress
import secrets
import base64
import requests
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from contextlib import contextmanager

from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import redis
import jwt
import bcrypt

# =============================================================
# CONFIGURATION AVEC VARIABLES D'ENVIRONNEMENT
# =============================================================

class Config:
    """Configuration centralisée de l'API - 100% sécurisée pour GitHub"""
    
    # Sécurité - À METTRE DANS .env
    SECRET_KEY = os.environ.get('SECRET_KEY', 'CHANGE_THIS_IN_PRODUCTION_9f7e8d2a4b6c1e3f')
    JWT_SECRET = os.environ.get('JWT_SECRET', 'CHANGE_THIS_IN_PRODUCTION_jwt_super_secret')
    
    # PayPal Configuration - À METTRE DANS .env
    PAYPAL_MODE = os.environ.get('PAYPAL_MODE', 'sandbox')  # 'sandbox' ou 'live'
    PAYPAL_CLIENT_ID = os.environ.get('PAYPAL_CLIENT_ID', '')
    PAYPAL_CLIENT_SECRET = os.environ.get('PAYPAL_CLIENT_SECRET', '')
    PAYPAL_WEBHOOK_ID = os.environ.get('PAYPAL_WEBHOOK_ID', '')
    
    # Base de données
    DB_PATH = os.environ.get('DB_PATH', 'olysacheck_keys.db')
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    # Quotas par défaut
    DEFAULT_QUOTA = int(os.environ.get('DEFAULT_QUOTA', 10000))
    DAILY_LIMIT = int(os.environ.get('DAILY_LIMIT', 500))
    RATE_LIMIT = os.environ.get('RATE_LIMIT', "10 per second")
    
    # Sécurité
    MAX_ATTEMPTS = int(os.environ.get('MAX_ATTEMPTS', 5))
    BLOCK_DURATION = int(os.environ.get('BLOCK_DURATION', 900))  # 15 minutes
    TOKEN_EXPIRY = int(os.environ.get('TOKEN_EXPIRY', 86400))    # 24 heures
    
    # Logging
    LOG_FILE = os.environ.get('LOG_FILE', 'api_validator.log')
    LOG_LEVEL = getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper())
    
    # Mode debug
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

# =============================================================
# INITIALISATION FLASK
# =============================================================

app = Flask(__name__)
app.config.from_object(Config)

# CORS avec origines configurables
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'https://olysacheck.vercel.app,http://localhost:5000').split(',')
CORS(app, origins=ALLOWED_ORIGINS)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[Config.RATE_LIMIT],
    storage_uri=Config.REDIS_URL
)

# Configuration logging
logging.basicConfig(
    level=Config.LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("APIValidator")

# =============================================================
# GESTIONNAIRE PAYPAL
# =============================================================

class PayPalManager:
    """Gestionnaire des paiements PayPal avec validation sécurisée"""
    
    def __init__(self):
        self.access_token = None
        self.token_expiry = None
        
        if Config.PAYPAL_MODE == 'live':
            self.api_base = 'https://api-m.paypal.com'
        else:
            self.api_base = 'https://api-m.sandbox.paypal.com'
    
    def get_access_token(self):
        """Obtient un token d'accès OAuth2 pour PayPal"""
        if self.access_token and self.token_expiry and datetime.now() < self.token_expiry:
            return self.access_token
        
        try:
            auth = base64.b64encode(f"{Config.PAYPAL_CLIENT_ID}:{Config.PAYPAL_CLIENT_SECRET}".encode()).decode()
            
            response = requests.post(
                f"{self.api_base}/v1/oauth2/token",
                headers={
                    'Authorization': f'Basic {auth}',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data={'grant_type': 'client_credentials'},
                timeout=10
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self.access_token = token_data['access_token']
                self.token_expiry = datetime.now() + timedelta(seconds=token_data['expires_in'] - 300)
                logger.info("✅ Token PayPal obtenu")
                return self.access_token
            else:
                logger.error(f"❌ Erreur obtention token PayPal: {response.text}")
                return None
        except Exception as e:
            logger.error(f"❌ Exception token PayPal: {e}")
            return None
    
    def verify_transaction(self, transaction_id):
        """
        Vérifie une transaction PayPal
        Retourne: (is_valid, transaction_data, message)
        """
        token = self.get_access_token()
        if not token:
            return False, None, "Impossible d'obtenir token d'accès"
        
        try:
            response = requests.get(
                f"{self.api_base}/v2/checkout/orders/{transaction_id}",
                headers={
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json'
                },
                timeout=10
            )
            
            if response.status_code == 200:
                transaction = response.json()
                
                # Vérifier le statut
                if transaction.get('status') != 'COMPLETED':
                    return False, transaction, f"Statut: {transaction.get('status')}"
                
                # Vérifier le montant (2€)
                purchase_units = transaction.get('purchase_units', [])
                if not purchase_units:
                    return False, transaction, "Pas d'unités d'achat"
                
                amount = purchase_units[0].get('amount', {})
                value = amount.get('value')
                currency = amount.get('currency_code')
                
                if value != '2.00' or currency != 'EUR':
                    return False, transaction, f"Montant incorrect: {value} {currency}"
                
                # Tout est bon
                return True, transaction, "Transaction valide"
            else:
                return False, None, f"Transaction non trouvée (code {response.status_code})"
                
        except requests.exceptions.Timeout:
            return False, None, "Timeout lors de la vérification"
        except Exception as e:
            logger.error(f"❌ Erreur vérification transaction: {e}")
            return False, None, str(e)

# =============================================================
# BASE DE DONNÉES SQLITE
# =============================================================

class DatabaseManager:
    """Gestionnaire de base de données SQLite avec connexion sécurisée"""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager pour les connexions DB"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def init_database(self):
        """Initialise les tables nécessaires"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # =========================================================
            # CRÉATION DES TABLES (SANS INDEX DANS LE CREATE TABLE)
            # =========================================================
            
            # Table des clés API (avec payment_id)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id VARCHAR(32) UNIQUE NOT NULL,
                    api_key VARCHAR(64) UNIQUE NOT NULL,
                    email VARCHAR(255),
                    plan_type VARCHAR(20) DEFAULT 'premium',
                    monthly_quota INTEGER DEFAULT 10000,
                    requests_used INTEGER DEFAULT 0,
                    daily_requests INTEGER DEFAULT 0,
                    last_request DATETIME,
                    daily_reset DATE DEFAULT CURRENT_DATE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME,
                    is_active BOOLEAN DEFAULT 1,
                    is_revoked BOOLEAN DEFAULT 0,
                    payment_id VARCHAR(100) UNIQUE
                )
            """)
            
            # Table des requêtes (logging)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id VARCHAR(32),
                    endpoint VARCHAR(100),
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    status_code INTEGER,
                    response_time_ms INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (key_id) REFERENCES api_keys(key_id)
                )
            """)
            
            # Table des tentatives de brute force
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS brute_force_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address VARCHAR(45) NOT NULL,
                    attempt_count INTEGER DEFAULT 1,
                    first_attempt DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_attempt DATETIME DEFAULT CURRENT_TIMESTAMP,
                    blocked_until DATETIME
                )
            """)
            
            # Table des webhooks (pour le paiement)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS payment_webhooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_id VARCHAR(100) UNIQUE,
                    key_id VARCHAR(32),
                    email VARCHAR(255),
                    amount DECIMAL(10,2),
                    currency VARCHAR(3) DEFAULT 'EUR',
                    status VARCHAR(20),
                    payload TEXT,
                    verified BOOLEAN DEFAULT 0,
                    processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # =========================================================
            # CRÉATION DES INDEX (APRÈS LES TABLES)
            # =========================================================
            
            # Index pour api_keys
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_key ON api_keys(api_key)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_key_id ON api_keys(key_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_payment ON api_keys(payment_id)")
            
            # Index pour api_requests
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_key_time ON api_requests(key_id, created_at)")
            
            # Index pour brute_force_attempts
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip ON brute_force_attempts(ip_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked ON brute_force_attempts(blocked_until)")
            
            # Index pour payment_webhooks
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_transaction ON payment_webhooks(transaction_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_key ON payment_webhooks(key_id)")
            
            # =========================================================
            # VUE DES STATISTIQUES
            # =========================================================
            
            cursor.execute("""
                CREATE VIEW IF NOT EXISTS api_stats AS
                SELECT 
                    COUNT(DISTINCT key_id) as total_keys,
                    SUM(CASE WHEN is_active AND NOT is_revoked THEN 1 ELSE 0 END) as active_keys,
                    SUM(CASE WHEN expires_at < CURRENT_TIMESTAMP THEN 1 ELSE 0 END) as expired_keys,
                    AVG(requests_used) as avg_usage,
                    SUM(requests_used) as total_requests
                FROM api_keys
            """)
            
            conn.commit()
            logger.info("✅ Base de données initialisée")

# =============================================================
# GESTIONNAIRE DE CLÉS
# =============================================================

class KeyManager:
    """Gestionnaire des clés API avec validation et quotas"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.redis_client = None
        self._init_redis()
    
    def _init_redis(self):
        """Initialise Redis pour le cache si disponible"""
        try:
            self.redis_client = redis.from_url(app.config['REDIS_URL'])
            self.redis_client.ping()
            logger.info("✅ Redis connecté")
        except:
            logger.warning("⚠️ Redis non disponible, utilisation du cache mémoire")
            self.redis_client = None
    
    def generate_key_id(self, api_key):
        """Génère un ID unique pour la clé"""
        return hashlib.sha256(api_key.encode()).hexdigest()[:16]
    
    def generate_api_key(self):
        """Génère une clé API sécurisée"""
        return f"oly_{secrets.token_urlsafe(32)}"
    
    def store_new_key(self, api_key, email=None, plan='premium', quota=None, payment_id=None):
        """Stocke une nouvelle clé API après paiement"""
        try:
            key_id = self.generate_key_id(api_key)
            expires_at = datetime.now() + timedelta(days=30)
            
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO api_keys 
                    (key_id, api_key, email, plan_type, monthly_quota, expires_at, payment_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    key_id, 
                    api_key, 
                    email, 
                    plan, 
                    quota or Config.DEFAULT_QUOTA,
                    expires_at.isoformat(),
                    payment_id
                ))
                conn.commit()
                
                logger.info(f"✅ Nouvelle clé stockée: {key_id[:8]}...")
                return key_id
                
        except sqlite3.IntegrityError:
            logger.error(f"❌ Clé déjà existante: {api_key[:8]}...")
            return None
        except Exception as e:
            logger.error(f"❌ Erreur stockage clé: {e}")
            return None
    
    def validate_key(self, api_key, endpoint, ip_address):
        """Valide une clé API avec vérification complète"""
        
        # Vérification format
        if not api_key or not api_key.startswith('oly_'):
            return False, "Format de clé invalide"
        
        key_id = self.generate_key_id(api_key)
        
        # Vérification cache Redis
        if self.redis_client:
            cache_key = f"key:{key_id}"
            cached = self.redis_client.get(cache_key)
            if cached:
                return json.loads(cached)
        
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            # Récupérer la clé
            cursor.execute("""
                SELECT * FROM api_keys 
                WHERE api_key = ? AND is_active = 1 AND is_revoked = 0
            """, (api_key,))
            
            key_data = cursor.fetchone()
            
            if not key_data:
                self._log_attempt(ip_address, api_key, False)
                return False, "Clé invalide ou désactivée"
            
            # Vérifier expiration
            expires_at = datetime.fromisoformat(key_data['expires_at'])
            if expires_at < datetime.now():
                return False, "Clé expirée"
            
            # Vérifier quota mensuel
            if key_data['requests_used'] >= key_data['monthly_quota']:
                return False, "Quota mensuel dépassé"
            
            # Vérifier quota quotidien
            today = datetime.now().date()
            if key_data['daily_reset'] == today.isoformat():
                if key_data['daily_requests'] >= Config.DAILY_LIMIT:
                    return False, "Limite quotidienne atteinte"
            else:
                # Reset du compteur quotidien
                cursor.execute("""
                    UPDATE api_keys 
                    SET daily_requests = 0, daily_reset = ?
                    WHERE key_id = ?
                """, (today.isoformat(), key_id))
            
            # Mettre à jour les compteurs
            cursor.execute("""
                UPDATE api_keys 
                SET requests_used = requests_used + 1,
                    daily_requests = daily_requests + 1,
                    last_request = CURRENT_TIMESTAMP
                WHERE key_id = ?
            """, (key_id,))
            
            # Log de la requête
            self._log_request(key_id, endpoint, ip_address, 200)
            
            # Mettre en cache
            if self.redis_client:
                result = {
                    'valid': True,
                    'key_id': key_id,
                    'plan': key_data['plan_type'],
                    'requests_left': key_data['monthly_quota'] - key_data['requests_used'] - 1
                }
                self.redis_client.setex(cache_key, 300, json.dumps(result))
            
            conn.commit()
            
            return True, {
                'key_id': key_id,
                'plan': key_data['plan_type'],
                'requests_left': key_data['monthly_quota'] - key_data['requests_used'] - 1,
                'expires_at': key_data['expires_at']
            }
    
    def _log_request(self, key_id, endpoint, ip_address, status):
        """Log une requête API"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO api_requests 
                (key_id, endpoint, ip_address, status_code, response_time_ms)
                VALUES (?, ?, ?, ?, ?)
            """, (key_id, endpoint, ip_address, status, 0))
    
    def _log_attempt(self, ip_address, api_key, success):
        """Log une tentative d'authentification"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            # Vérifier si l'IP est déjà dans la table brute_force
            cursor.execute("""
                SELECT * FROM brute_force_attempts 
                WHERE ip_address = ?
            """, (ip_address,))
            
            attempt = cursor.fetchone()
            
            if attempt:
                if not success:
                    cursor.execute("""
                        UPDATE brute_force_attempts 
                        SET attempt_count = attempt_count + 1,
                            last_attempt = CURRENT_TIMESTAMP
                        WHERE ip_address = ?
                    """, (ip_address,))
            else:
                if not success:
                    cursor.execute("""
                        INSERT INTO brute_force_attempts (ip_address)
                        VALUES (?)
                    """, (ip_address,))
    
    def revoke_key(self, api_key):
        """Révoque une clé API"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE api_keys 
                SET is_revoked = 1 
                WHERE api_key = ?
            """, (api_key,))
            
            if cursor.rowcount > 0:
                logger.warning(f"🚫 Clé révoquée: {api_key[:8]}...")
                return True
            return False
    
    def get_stats(self, key_id=None):
        """Récupère les statistiques d'utilisation"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            if key_id:
                cursor.execute("""
                    SELECT * FROM api_keys WHERE key_id = ?
                """, (key_id,))
                return dict(cursor.fetchone())
            else:
                cursor.execute("SELECT * FROM api_stats")
                return dict(cursor.fetchone())
    
    def get_key_by_payment(self, payment_id):
        """Récupère une clé par ID de paiement"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT api_key FROM api_keys WHERE payment_id = ?
            """, (payment_id,))
            result = cursor.fetchone()
            return result['api_key'] if result else None

# =============================================================
# MIDDLEWARES ET DÉCORATEURS
# =============================================================

def require_api_key(f):
    """Décorateur pour protéger les endpoints avec clé API"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({
                'success': False,
                'error': 'Clé API manquante'
            }), 401
        
        # Vérification brute force
        ip = request.remote_addr
        if is_ip_blocked(ip):
            return jsonify({
                'success': False,
                'error': 'Trop de tentatives. Réessayez plus tard.'
            }), 429
        
        valid, result = key_manager.validate_key(
            api_key, 
            request.path,
            ip
        )
        
        if not valid:
            return jsonify({
                'success': False,
                'error': result
            }), 403
        
        g.api_key_data = result
        return f(*args, **kwargs)
    
    return decorated

def is_ip_blocked(ip):
    """Vérifie si une IP est bloquée"""
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT blocked_until FROM brute_force_attempts 
            WHERE ip_address = ? AND blocked_until > CURRENT_TIMESTAMP
        """, (ip,))
        return cursor.fetchone() is not None

def block_ip(ip, duration=Config.BLOCK_DURATION):
    """Bloque une IP"""
    blocked_until = datetime.now() + timedelta(seconds=duration)
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE brute_force_attempts 
            SET blocked_until = ? 
            WHERE ip_address = ?
        """, (blocked_until.isoformat(), ip))

# =============================================================
# ENDPOINTS API
# =============================================================

db = DatabaseManager(Config.DB_PATH)
key_manager = KeyManager(db)
paypal_manager = PayPalManager()

@app.route('/health', methods=['GET'])
def health_check():
    """Endpoint de santé"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '3.0.0',
        'paypal_mode': Config.PAYPAL_MODE
    })

@app.route('/verify-payment', methods=['POST'])
@limiter.limit("5 per minute")
def verify_payment():
    """
    Vérifie un paiement PayPal et génère une clé API
    C'est l'endpoint appelé par le frontend après redirection PayPal
    """
    try:
        data = request.get_json()
        
        if not data or 'transaction_id' not in data:
            return jsonify({
                'success': False,
                'error': 'ID de transaction requis'
            }), 400
        
        transaction_id = data['transaction_id']
        email = data.get('email', '')
        
        logger.info(f"🔍 Vérification paiement: {transaction_id}")
        
        # Vérifier si cette transaction a déjà été traitée
        existing_key = key_manager.get_key_by_payment(transaction_id)
        if existing_key:
            logger.info(f"✅ Transaction déjà traitée: {transaction_id}")
            return jsonify({
                'success': True,
                'api_key': existing_key,
                'message': 'Paiement déjà validé'
            })
        
        # Vérifier la transaction avec PayPal
        is_valid, transaction, message = paypal_manager.verify_transaction(transaction_id)
        
        if not is_valid:
            logger.warning(f"🚫 Transaction invalide {transaction_id}: {message}")
            
            # Enregistrer la tentative échouée
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO payment_webhooks 
                    (transaction_id, email, status, payload)
                    VALUES (?, ?, ?, ?)
                """, (
                    transaction_id,
                    email,
                    'INVALID',
                    json.dumps({'error': message, 'transaction': transaction})
                ))
            
            return jsonify({
                'success': False,
                'error': f'Transaction invalide: {message}'
            }), 400
        
        # Transaction valide - Générer une clé API
        api_key = key_manager.generate_api_key()
        
        # Stocker la clé avec l'ID de transaction
        key_id = key_manager.store_new_key(
            api_key=api_key,
            email=email,
            plan='premium',
            payment_id=transaction_id
        )
        
        if not key_id:
            return jsonify({
                'success': False,
                'error': 'Erreur lors de la création de la clé'
            }), 500
        
        # Enregistrer le webhook
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO payment_webhooks 
                (transaction_id, key_id, email, amount, currency, status, payload, verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                transaction_id,
                key_id,
                email,
                '2.00',
                'EUR',
                'COMPLETED',
                json.dumps(transaction),
                1
            ))
        
        logger.info(f"💰 Paiement validé et clé générée: {transaction_id}")
        
        return jsonify({
            'success': True,
            'api_key': api_key,
            'message': 'Paiement validé avec succès'
        })
        
    except Exception as e:
        logger.error(f"❌ Erreur verify-payment: {e}")
        return jsonify({
            'success': False,
            'error': 'Erreur serveur lors de la vérification'
        }), 500

@app.route('/webhook/paypal', methods=['POST'])
def paypal_webhook():
    """
    Webhook pour recevoir les notifications PayPal
    Appelé automatiquement par PayPal après un paiement
    """
    try:
        webhook_data = request.get_json()
        event_type = webhook_data.get('event_type')
        
        logger.info(f"📨 Webhook PayPal reçu: {event_type}")
        
        # Sauvegarder le webhook
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO payment_webhooks 
                (transaction_id, status, payload)
                VALUES (?, ?, ?)
            """, (
                webhook_data.get('resource', {}).get('id'),
                event_type,
                json.dumps(webhook_data)
            ))
        
        return jsonify({'status': 'received'}), 200
        
    except Exception as e:
        logger.error(f"❌ Erreur webhook: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/validate_key', methods=['POST'])
@limiter.limit("5 per minute")
def validate_key_endpoint():
    """
    Endpoint public pour valider une clé API
    Utilisé par les clients pour vérifier leur clé
    """
    data = request.get_json()
    
    if not data or 'api_key' not in data:
        return jsonify({
            'success': False,
            'error': 'Clé API requise'
        }), 400
    
    api_key = data['api_key']
    ip = request.remote_addr
    
    # Vérification brute force
    if is_ip_blocked(ip):
        return jsonify({
            'success': False,
            'error': 'Trop de tentatives. Réessayez plus tard.'
        }), 429
    
    valid, result = key_manager.validate_key(
        api_key, 
        '/validate_key',
        ip
    )
    
    if valid:
        return jsonify({
            'success': True,
            'data': result
        })
    else:
        # Compter les tentatives échouées
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE brute_force_attempts 
                SET attempt_count = attempt_count + 1
                WHERE ip_address = ?
            """, (ip,))
            
            cursor.execute("""
                SELECT attempt_count FROM brute_force_attempts 
                WHERE ip_address = ?
            """, (ip,))
            
            attempt = cursor.fetchone()
            if attempt and attempt['attempt_count'] >= Config.MAX_ATTEMPTS:
                block_ip(ip)
        
        return jsonify({
            'success': False,
            'error': result
        }), 403

@app.route('/register_key', methods=['POST'])
@limiter.limit("10 per minute")
def register_key():
    """
    Endpoint pour enregistrer une nouvelle clé (appelé par le script de paiement)
    Protégé par un secret partagé
    """
    data = request.get_json()
    
    # Vérification du secret partagé
    auth_header = request.headers.get('Authorization')
    expected_secret = f"Bearer {app.config['SECRET_KEY']}"
    
    if auth_header != expected_secret:
        logger.warning(f"🚫 Tentative non autorisée depuis {request.remote_addr}")
        return jsonify({
            'success': False,
            'error': 'Non autorisé'
        }), 401
    
    if not data or 'api_key' not in data:
        return jsonify({
            'success': False,
            'error': 'Clé API requise'
        }), 400
    
    api_key = data['api_key']
    email = data.get('email')
    plan = data.get('plan', 'premium')
    
    # Stocker la clé
    key_id = key_manager.store_new_key(api_key, email, plan)
    
    if key_id:
        logger.info(f"✅ Nouvelle clé enregistrée depuis paiement: {key_id[:8]}...")
        return jsonify({
            'success': True,
            'key_id': key_id,
            'message': 'Clé enregistrée avec succès'
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Erreur lors de l\'enregistrement'
        }), 500

@app.route('/key_info/<key_id>', methods=['GET'])
@require_api_key
def key_info(key_id):
    """Récupère les informations d'une clé (protégé)"""
    stats = key_manager.get_stats(key_id)
    
    if stats:
        return jsonify({
            'success': True,
            'data': {
                'key_id': stats['key_id'],
                'plan': stats['plan_type'],
                'requests_used': stats['requests_used'],
                'monthly_quota': stats['monthly_quota'],
                'requests_left': stats['monthly_quota'] - stats['requests_used'],
                'expires_at': stats['expires_at'],
                'created_at': stats['created_at'],
                'last_request': stats['last_request']
            }
        })
    
    return jsonify({
        'success': False,
        'error': 'Clé non trouvée'
    }), 404

@app.route('/revoke_key', methods=['POST'])
@require_api_key
def revoke_key_endpoint():
    """Révoque une clé API (protégé)"""
    data = request.get_json()
    
    if not data or 'api_key' not in data:
        return jsonify({
            'success': False,
            'error': 'Clé API requise'
        }), 400
    
    # Vérification que c'est bien la même clé
    if data['api_key'] != request.headers.get('X-API-Key'):
        return jsonify({
            'success': False,
            'error': 'Vous ne pouvez révoquer que votre propre clé'
        }), 403
    
    if key_manager.revoke_key(data['api_key']):
        return jsonify({
            'success': True,
            'message': 'Clé révoquée avec succès'
        })
    
    return jsonify({
        'success': False,
        'error': 'Erreur lors de la révocation'
    }), 500

@app.route('/stats', methods=['GET'])
@require_api_key
def stats():
    """Statistiques globales (admin only)"""
    # Vérification que c'est une clé admin
    if g.api_key_data.get('plan') != 'enterprise':
        return jsonify({
            'success': False,
            'error': 'Accès réservé'
        }), 403
    
    stats = key_manager.get_stats()
    
    return jsonify({
        'success': True,
        'data': stats
    })

# =============================================================
# GESTION DES ERREURS
# =============================================================

@app.errorhandler(429)
def ratelimit_handler(e):
    """Gestionnaire de rate limiting"""
    return jsonify({
        'success': False,
        'error': 'Trop de requêtes. Veuillez ralentir.'
    }), 429

@app.errorhandler(500)
def internal_error(e):
    """Gestionnaire d'erreur 500"""
    logger.error(f"❌ Erreur 500: {e}")
    return jsonify({
        'success': False,
        'error': 'Erreur interne du serveur'
    }), 500

@app.errorhandler(404)
def not_found(e):
    """Gestionnaire 404"""
    return jsonify({
        'success': False,
        'error': 'Endpoint non trouvé'
    }), 404

# =============================================================
# TÂCHES DE FOND
# =============================================================

def cleanup_expired_keys():
    """Nettoie les clés expirées (à exécuter quotidiennement)"""
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE api_keys 
            SET is_active = 0 
            WHERE expires_at < CURRENT_TIMESTAMP
        """)
        expired = cursor.rowcount
        if expired > 0:
            logger.info(f"🧹 {expired} clés expirées désactivées")

def reset_daily_limits():
    """Réinitialise les limites quotidiennes"""
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE api_keys 
            SET daily_requests = 0,
                daily_reset = CURRENT_DATE
            WHERE daily_reset != CURRENT_DATE
        """)
        logger.info(f"📊 Limites quotidiennes réinitialisées")

# =============================================================
# POINT D'ENTRÉE PRINCIPAL
# =============================================================

if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║           🚀 OLYSACHECK API VALIDATOR v3.0.0 DÉMARRÉ                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  🔒 Mode PayPal: {mode}                                                     ║
║  ✅ Base de données: SQLite + Redis                                         ║
║  ✅ Protection brute force: ACTIVE                                          ║
║  ✅ Rate limiting: ACTIVE                                                   ║
║  ✅ Validation paiement: ACTIVE                                             ║
║  ✅ Webhook PayPal: PRÊT                                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """.format(mode=Config.PAYPAL_MODE.upper()))
    
    # Nettoyage initial
    cleanup_expired_keys()
    reset_daily_limits()
    
    # Lancement du serveur
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=Config.DEBUG,
        threaded=True
    )