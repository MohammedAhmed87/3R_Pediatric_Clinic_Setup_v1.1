import base64
from contextlib import contextmanager
import csv
import datetime
import functools
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import platform
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import webview

try:
  from cryptography.exceptions import InvalidSignature
  from cryptography.hazmat.primitives.asymmetric.ed25519 import (
      Ed25519PublicKey,
  )
  _CRYPTO_AVAILABLE = True
except Exception:
  _CRYPTO_AVAILABLE = False

# ---------------------------------------------------------
# تهيئة مسارات النظام والمجلدات المحلية
# ---------------------------------------------------------
APP_DATA_DIR = os.path.join(
    os.getenv('LOCALAPPDATA') or os.path.expanduser('~'), '3R_Clinic_System'
)
os.makedirs(APP_DATA_DIR, exist_ok=True)
CONFIG_FILE = os.path.join(APP_DATA_DIR, 'config.json')

# ---------------------------------------------------------
# نظام السجلات (Logging) - ملف app.log داخل مجلد logs
# ملاحظة: لا نسجل أسماء أو بيانات المرضى ولا كلمات المرور أبداً
# ---------------------------------------------------------
LOGS_DIR = os.path.join(APP_DATA_DIR, 'logs')
LOG_FILE = os.path.join(LOGS_DIR, 'app.log')

logger = logging.getLogger('clinic')
logger.setLevel(logging.INFO)
logger.propagate = False
if not logger.handlers:
  try:
    os.makedirs(LOGS_DIR, exist_ok=True)
    _file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=1_000_000, backupCount=5, encoding='utf-8'
    )
    _file_handler.setFormatter(
        logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s')
    )
    logger.addHandler(_file_handler)
  except Exception:
    # لو مفيش صلاحية كتابة، البرنامج يكمل شغل من غير سجلات
    logger.addHandler(logging.NullHandler())


def _log_uncaught(exc_type, exc_value, exc_tb):
  if issubclass(exc_type, KeyboardInterrupt):
    sys.__excepthook__(exc_type, exc_value, exc_tb)
    return
  logger.critical('Uncaught exception', exc_info=(exc_type, exc_value, exc_tb))


def _log_thread_uncaught(args):
  logger.critical(
      'Uncaught exception in thread',
      exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
  )


sys.excepthook = _log_uncaught
threading.excepthook = _log_thread_uncaught

DEFAULT_CONFIG = {
    'db_mode': 'local',
    'network_db_path': '',
    'backup_path': os.path.join(
        os.path.expanduser('~'), 'Desktop', '3R_Clinic_Backups'
    ),
}


def load_config():
  if not os.path.exists(CONFIG_FILE):
    save_config(DEFAULT_CONFIG)
    return DEFAULT_CONFIG
  try:
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
      return json.load(f)
  except Exception:
    return DEFAULT_CONFIG


def save_config(cfg):
  with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=4)


def get_db_path():
  cfg = load_config()
  if cfg.get('db_mode') == 'network' and cfg.get('network_db_path'):
    return cfg.get('network_db_path')
  return os.path.join(APP_DATA_DIR, 'clinic.db')


PATIENTS_ATTACHMENTS_DIR = os.path.join(APP_DATA_DIR, 'Patient_Attachments')
os.makedirs(PATIENTS_ATTACHMENTS_DIR, exist_ok=True)


def hash_pass(password):
  """التشفير القديم (SHA-256 بدون ملح). موجود فقط لدعم حسابات قديمة."""
  return hashlib.sha256(password.encode('utf-8')).hexdigest()


PBKDF2_ITERATIONS = 200_000


def hash_password_new(password, salt=None):
  """تشفير الباسورد الحالي: PBKDF2-HMAC-SHA256 مع ملح عشوائي خاص بكل مستخدم."""
  salt = salt or secrets.token_bytes(16)
  digest = hashlib.pbkdf2_hmac(
      'sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS
  )
  return f'pbkdf2${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}'


def verify_password(stored_hash, password):
  """يرجع (صح_أم_لا, لازم_ترقية). الترقية تحصل تلقائياً بعد أول دخول ناجح."""
  if stored_hash and stored_hash.startswith('pbkdf2$'):
    try:
      _, iterations, salt_hex, digest_hex = stored_hash.split('$')
      salt = bytes.fromhex(salt_hex)
      check = hashlib.pbkdf2_hmac(
          'sha256', password.encode('utf-8'), salt, int(iterations)
      )
      return secrets.compare_digest(check.hex(), digest_hex), False
    except Exception:
      return False, False
  # حساب قديم بتشفير SHA-256 بدون ملح
  return secrets.compare_digest(hash_pass(password), stored_hash or ''), True


def open_file_or_folder(path):
  """فتح الملف أو المجلد تلقائياً في نظام التشغيل"""
  try:
    if os.name == 'nt':
      os.startfile(path)
    elif platform.system() == 'Darwin':
      subprocess.Popen(['open', path])
    else:
      subprocess.Popen(['xdg-open', path])
  except Exception as e:
    logger.exception('Failed to open file or folder')


@contextmanager
def get_db():
  """إدارة اتصال قاعدة البيانات وإغلاقه تلقائياً لمنع قفل الملف"""
  conn = sqlite3.connect(get_db_path())
  conn.execute('PRAGMA journal_mode=WAL;')
  conn.row_factory = sqlite3.Row
  try:
    yield conn
  finally:
    conn.close()


# ---------------------------------------------------------
# نظام إصدارات قاعدة البيانات (Schema Migrations)
# كل تعديل مستقبلي على الجداول يتضاف كدالة migration جديدة في آخر القائمة
# ولا نعدّل أبداً في migration قديمة اتطبقت عند عملاء.
# رقم الإصدار محفوظ داخل ملف القاعدة نفسه (PRAGMA user_version).
# ---------------------------------------------------------
class SchemaTooNewError(Exception):
  """قاعدة البيانات اتحدّثت بنسخة أحدث من البرنامج الحالي."""


def _fatal_dialog(title, message):
  """رسالة خطأ واضحة للمستخدم قبل إغلاق البرنامج (بدون console)."""
  try:
    if os.name == 'nt':
      import ctypes

      ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)
    else:
      sys.stderr.write(f'{title}\n{message}\n')
  except Exception:
    pass


def _migration_v1_baseline(conn):
  """الإصدار 1: الجداول الأساسية (المرضى، المتابعات، المستخدمين)."""
  # جدول المرضى الشامل
  conn.execute("""
            CREATE TABLE IF NOT EXISTS patients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT, name TEXT NOT NULL, dob TEXT, age TEXT, residence TEXT, contact TEXT, date_of_visit TEXT, local_folder TEXT,
                chief_complaint TEXT, onset TEXT, duration TEXT, severity TEXT, frequency TEXT, progression TEXT, alleviating_factors TEXT, aggravating_factors TEXT, other_systems TEXT,
                sym_syncope TEXT, sym_palpitations TEXT, sym_chest_pain TEXT, sym_dyspnea TEXT, sym_orthopnea TEXT, sym_edema TEXT, sym_low_cop TEXT, sym_cyanosis TEXT,
                past_medical TEXT, past_surgical TEXT, hospitalizations TEXT, dev_delay TEXT, medications TEXT, natal_events TEXT, allergies TEXT, consanguinity TEXT, scd TEXT, family_history TEXT,
                ecg TEXT, holter TEXT, echo TEXT, inv_other TEXT,
                lab_hb TEXT, lab_tlc TEXT, lab_plt TEXT, lab_t3 TEXT, lab_t4 TEXT, lab_tsh TEXT, lab_na TEXT, lab_k TEXT, lab_mg TEXT, lab_hpylori TEXT, lab_other TEXT, lab_compliance TEXT,
                diagnosis TEXT, treatment TEXT, plan TEXT, status TEXT
            )
        """)

  # جدول زيارات المتابعة
  conn.execute("""
            CREATE TABLE IF NOT EXISTS followups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER, visit_date TEXT, reason TEXT, plan_change TEXT, weight_bsa TEXT,
                FOREIGN KEY (patient_id) REFERENCES patients (id) ON DELETE CASCADE
            )
        """)

  # جدول المستخدمين والصلاحيات
  conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)


def _migration_v2_code_counter(conn):
  """الإصدار 2: جدول إعدادات + عداد أكواد المرضى (عشان الكود لا يتكرر بعد الحذف)."""
  conn.execute(
      'CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)'
  )
  highest = _highest_patient_code_number(conn.cursor())
  conn.execute(
      "INSERT OR IGNORE INTO settings (key, value) VALUES ('patient_code_seq', ?)",
      (str(highest),),
  )


def _migration_v3_secure_auth(conn):
  """الإصدار 3: إزالة حساب الصيانة السري القديم، وترقية تشفير الحسابات التجريبية."""
  conn.execute("DELETE FROM users WHERE username='superadmin'")
  for uname, default_pw in (
      ('admin', 'admin123'),
      ('doctor', 'doc123'),
      ('staff', 'staff123'),
  ):
    old_hash = hash_pass(default_pw)
    conn.execute(
        'UPDATE users SET password=? WHERE username=? AND password=?',
        (hash_password_new(default_pw), uname, old_hash),
    )


def _migration_v4_role_permissions(conn):
  """الإصدار 4: صلاحيات كل دور (Doctor/Staff) تتحدد من البرنامج نفسه، مش ثابتة بالكود."""
  conn.execute("""
      CREATE TABLE IF NOT EXISTS role_permissions (
          role TEXT PRIMARY KEY,
          add_patient INTEGER NOT NULL DEFAULT 0,
          edit_patient INTEGER NOT NULL DEFAULT 0,
          delete_patient INTEGER NOT NULL DEFAULT 0,
          add_followup INTEGER NOT NULL DEFAULT 0,
          export_data INTEGER NOT NULL DEFAULT 0,
          manage_settings INTEGER NOT NULL DEFAULT 0,
          manage_users INTEGER NOT NULL DEFAULT 0
      )
  """)
  # نفس الصلاحيات الافتراضية اللي كانت شغالة قبل كده بالظبط، عشان محدش
  # ياخد صلاحية زيادة فجأة بعد التحديث. تقدر تغيّرها من شاشة الإعدادات.
  conn.execute(
      'INSERT OR IGNORE INTO role_permissions'
      ' (role, add_patient, edit_patient, delete_patient, add_followup,'
      '  export_data, manage_settings, manage_users)'
      ' VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      ('Doctor', 1, 1, 0, 1, 1, 0, 0),
  )
  conn.execute(
      'INSERT OR IGNORE INTO role_permissions'
      ' (role, add_patient, edit_patient, delete_patient, add_followup,'
      '  export_data, manage_settings, manage_users)'
      ' VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      ('Staff', 1, 0, 0, 1, 0, 0, 0),
  )


MIGRATIONS = [
    (1, _migration_v1_baseline),
    (2, _migration_v2_code_counter),
    (3, _migration_v3_secure_auth),
    (4, _migration_v4_role_permissions),
]
LATEST_SCHEMA_VERSION = MIGRATIONS[-1][0]
MAX_PRE_MIGRATION_BACKUPS = 5


def _backup_before_migration(conn, from_version):
  """نسخة أمان كاملة من القاعدة قبل أي تحديث لبنيتها."""
  backup_dir = os.path.join(APP_DATA_DIR, 'backups_pre_migration')
  os.makedirs(backup_dir, exist_ok=True)
  stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
  backup_path = os.path.join(backup_dir, f'clinic_v{from_version}_{stamp}.db')
  target = sqlite3.connect(backup_path)
  try:
    conn.backup(target)
  finally:
    target.close()
  logger.info('Pre-migration backup created: %s', backup_path)

  old_files = sorted(
      f for f in os.listdir(backup_dir)
      if f.startswith('clinic_v') and f.endswith('.db')
  )
  for old in old_files[:-MAX_PRE_MIGRATION_BACKUPS]:
    try:
      os.remove(os.path.join(backup_dir, old))
    except OSError:
      pass


def run_migrations(conn):
  current = conn.execute('PRAGMA user_version').fetchone()[0]
  if current > LATEST_SCHEMA_VERSION:
    raise SchemaTooNewError(
        f'db_version={current}, app_supports_up_to={LATEST_SCHEMA_VERSION}'
    )

  pending = [(v, fn) for v, fn in MIGRATIONS if v > current]
  if not pending:
    return

  has_data = conn.execute(
      "SELECT 1 FROM sqlite_master WHERE type='table' AND name='patients'"
  ).fetchone()
  if has_data:
    _backup_before_migration(conn, current)

  previous_isolation = conn.isolation_level
  conn.isolation_level = None  # تحكم يدوي في المعاملة
  try:
    for version, migrate in pending:
      conn.execute('BEGIN IMMEDIATE')
      try:
        migrate(conn)
        conn.execute(f'PRAGMA user_version = {int(version)}')
        conn.execute('COMMIT')
      except Exception:
        conn.execute('ROLLBACK')
        logger.exception('Migration to v%s failed and was rolled back', version)
        raise
      logger.info('Database schema migrated to v%s', version)
  finally:
    conn.isolation_level = previous_isolation


def init_db():
  """يجهّز قاعدة البيانات. يرجع True لو تمام، وFalse لو فشل (والتفاصيل في app.log)."""
  try:
    with get_db() as conn:
      run_migrations(conn)
      cursor = conn.cursor()

      # مفيش حسابات افتراضية تتضاف تلقائياً بعد كده؛ أول تشغيل بيطلب من العيادة
      # تعمل حساب Admin بنفسها (شاشة الإعداد الأولي في الواجهة).

      conn.commit()
    return True
  except SchemaTooNewError as e:
    logger.critical('Database is newer than this app: %s', e)
    _fatal_dialog(
        'قاعدة البيانات أحدث من نسخة البرنامج',
        'قاعدة البيانات دي اتحدّثت بنسخة أحدث من البرنامج.\n'
        'من فضلك حدّث البرنامج على هذا الجهاز لآخر إصدار قبل الاستخدام، '
        'عشان متتلفش بيانات المرضى.',
    )
    return False
  except Exception:
    logger.exception('Database init failed')
    _fatal_dialog(
        'تعذر تجهيز قاعدة البيانات',
        f'حصل خطأ أثناء تجهيز قاعدة البيانات.\nتفاصيل الخطأ في الملف:\n{LOG_FILE}',
    )
    return False


def get_logo_base64():
  # في النسخة المبنية بـ PyInstaller 6+ الملفات المضافة (datas) بتتحط جوه
  # فولدر _internal (sys._MEIPASS) مش جنب الـ exe، فنبحث في الاتنين.
  candidates = []
  if getattr(sys, 'frozen', False):
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass:
      candidates.append(meipass)
    candidates.append(os.path.dirname(sys.executable))
  else:
    candidates.append(os.path.dirname(os.path.abspath(__file__)))

  for base_dir in candidates:
    logo_path = os.path.join(base_dir, 'logo.png')
    if os.path.exists(logo_path):
      try:
        with open(logo_path, 'rb') as img_f:
          return 'data:image/png;base64,' + base64.b64encode(
              img_f.read()
          ).decode('utf-8')
      except Exception:
        continue
  return ''


# ---------------------------------------------------------
# API التواصل بين الـ Python و واجهة JavaScript
# ---------------------------------------------------------
# ---------------------------------------------------------
# نظام استرجاع الدخول (وضع الصيانة) بدون إنترنت
# المفتاح العام هنا للتحقق فقط، ولا يمكن توليد كود فتح منه.
# المفتاح الخاص المقابل محفوظ عند محمد فقط، خارج هذا البرنامج تماماً.
# ---------------------------------------------------------
MASTER_PUBLIC_KEY_HEX = '5979a993760a79646e56faab4edea70585d31d9733140e70a19a04fb1581b936'


def _verify_master_signature(challenge_text, signature_hex):
  if not _CRYPTO_AVAILABLE:
    return False
  try:
    pub = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(MASTER_PUBLIC_KEY_HEX)
    )
    pub.verify(bytes.fromhex(signature_hex), challenge_text.encode('utf-8'))
    return True
  except (InvalidSignature, ValueError, Exception):
    return False


PATIENT_CODE_PREFIX = 'P-'
_PATIENT_CODE_PATTERN = re.compile(r'^\s*P-(\d+)\s*$', re.IGNORECASE)


def _highest_patient_code_number(cursor):
  """أعلى رقم موجود حالياً بين الأكواد بصيغة P-<رقم>."""
  cursor.execute('SELECT code FROM patients')
  highest = 0
  for row in cursor.fetchall():
    match = _PATIENT_CODE_PATTERN.match(row[0] or '')
    if match:
      highest = max(highest, int(match.group(1)))
  return highest


def _read_patient_code_seq(cursor):
  try:
    cursor.execute("SELECT value FROM settings WHERE key='patient_code_seq'")
    row = cursor.fetchone()
    return int(row[0]) if row else 0
  except (sqlite3.Error, ValueError):
    return 0


def _next_patient_code(cursor):
  """يقترح الكود التالي P-01, P-02 ... (لا يعيد كوداً اتحذف مريضه)."""
  highest = max(
      _highest_patient_code_number(cursor), _read_patient_code_seq(cursor)
  )
  return f'{PATIENT_CODE_PREFIX}{highest + 1:02d}'


def _bump_patient_code_seq(cursor, code):
  """يرفع العداد لو الكود المحفوظ أعلى من العداد الحالي."""
  match = _PATIENT_CODE_PATTERN.match(code or '')
  if not match:
    return
  new_value = max(int(match.group(1)), _read_patient_code_seq(cursor))
  cursor.execute(
      'INSERT OR REPLACE INTO settings (key, value) VALUES'
      " ('patient_code_seq', ?)",
      (str(new_value),),
  )


# ---------------------------------------------------------
# فحص الصلاحيات (نفس قواعد الواجهة checkPermission، لكن داخل Python
# عشان محدش يقدر يتخطاها بتعديل الواجهة أو استدعاء الدالة مباشرة)
# ---------------------------------------------------------
# خريطة اسم الصلاحية في الكود -> اسم العمود في جدول role_permissions
ACTION_TO_COLUMN = {
    'add': 'add_patient',
    'edit': 'edit_patient',
    'delete': 'delete_patient',
    'followup': 'add_followup',
    'export': 'export_data',
    'settings': 'manage_settings',
    'manage_users': 'manage_users',
}

PERMISSION_DENIED_MESSAGES = {
    'delete': 'عفواً، لا تملك صلاحية حذف المرضى',
    'edit': 'عفواً، لا تملك صلاحية تعديل بيانات المرضى',
    'add': 'عفواً، لا تملك صلاحية إضافة مرضى',
    'settings': 'عفواً، لا تملك صلاحية إعدادات السيرفر والنسخ الاحتياطي',
    'export': 'عفواً، لا تملك صلاحية تصدير البيانات',
    'followup': 'عفواً، لا تملك صلاحية إضافة متابعات',
    'manage_users': 'عفواً، لا تملك صلاحية إدارة المستخدمين',
}


def _role_allows(role, action):
  """Admin دايماً كل الصلاحيات. غير كده بيتقرأ من جدول role_permissions
  اللي العيادة (المدير) هو اللي بيتحكم فيه من شاشة الإعدادات."""
  if role == 'Admin':
    return True
  column = ACTION_TO_COLUMN.get(action)
  if not column:
    return False
  try:
    with get_db() as conn:
      row = conn.execute(
          f'SELECT {column} FROM role_permissions WHERE role=?', (role,)
      ).fetchone()
      return bool(row[0]) if row else False
  except sqlite3.Error:
    logger.exception('Permission lookup failed for role=%s action=%s', role, action)
    return False


def _requires_permission(action):
  """ديكوريتور: يرفض استدعاء الدالة لو المستخدم الحالي مايملكش الصلاحية."""

  def decorator(fn):
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
      role = getattr(self, '_current_role', None)
      if role is None:
        return {'status': 'error', 'message': 'لازم تسجل الدخول أولاً'}
      if not _role_allows(role, action):
        logger.warning(
            'Permission denied: user=%s role=%s action=%s',
            getattr(self, '_current_user', '?'), role, action,
        )
        return {
            'status': 'error',
            'message': PERMISSION_DENIED_MESSAGES.get(
                action, 'عفواً، لا تملك الصلاحية الكافية'
            ),
        }
      return fn(self, *args, **kwargs)

    return wrapper

  return decorator


class ClinicAPI:

  def __init__(self):
    self._current_user = None
    self._current_role = None
    self._recovery_challenges = {}

  def has_any_user(self):
    with get_db() as conn:
      return conn.execute('SELECT COUNT(*) FROM users').fetchone()[0] > 0

  def create_first_admin(self, username, password):
    """يُستخدم فقط في شاشة الإعداد الأولي، ولو مفيش أي مستخدم مسجل بعد."""
    username = (username or '').strip()
    if len(username) < 3:
      return {'status': 'error', 'message': 'اسم المستخدم قصير جداً'}
    if len(password or '') < 6:
      return {
          'status': 'error',
          'message': 'كلمة السر يجب ألا تقل عن 6 خانات',
      }
    with get_db() as conn:
      if conn.execute('SELECT COUNT(*) FROM users').fetchone()[0] > 0:
        return {
            'status': 'error',
            'message': 'يوجد حساب بالفعل، لا يمكن إنشاء حساب أولي مرة أخرى',
        }
      conn.execute(
          "INSERT INTO users (username, password, role) VALUES (?, ?,"
          " 'Admin')",
          (username, hash_password_new(password)),
      )
      conn.commit()
      return {'status': 'success'}

  def login_user(self, username, password):
    try:
      with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT id, username, role, password FROM users WHERE username=?',
            (username,),
        )
        row = cursor.fetchone()
        if not row:
          return {
              'status': 'error',
              'message': 'اسم المستخدم أو كلمة السر غير صحيحة!',
          }
        ok, needs_upgrade = verify_password(row['password'], password)
        if not ok:
          return {
              'status': 'error',
              'message': 'اسم المستخدم أو كلمة السر غير صحيحة!',
          }
        if needs_upgrade:
          cursor.execute(
              'UPDATE users SET password=? WHERE id=?',
              (hash_password_new(password), row['id']),
          )
          conn.commit()
        self._current_user = row['username']
        self._current_role = row['role']
        return {
            'status': 'success',
            'username': row['username'],
            'role': row['role'],
        }
    except Exception as e:
      logger.exception('login_user crashed')
      return {'status': 'error', 'message': f'خطأ في الاتصال: {str(e)}'}

  def logout(self):
    self._current_user = None
    self._current_role = None
    return {'status': 'success'}

  def get_config(self):
    return load_config()

  @_requires_permission('settings')
  def save_server_config(self, db_mode, network_path, backup_path):
    cfg = load_config()
    cfg['db_mode'] = db_mode
    cfg['network_db_path'] = network_path
    cfg['backup_path'] = backup_path
    save_config(cfg)
    return {
        'status': 'success',
        'message': 'تم حفظ الإعدادات بنجاح وتطبيق المسار تلقائياً.',
    }

  @_requires_permission('settings')
  def execute_backup_now(self):
    try:
      cfg = load_config()
      target_dir = cfg.get('backup_path')
      if not target_dir:
        user_home = os.path.expanduser('~')
        onedrive_p = os.path.join(
            user_home, 'OneDrive', 'Desktop', '3R_Clinic_Backups'
        )
        standard_p = os.path.join(user_home, 'Desktop', '3R_Clinic_Backups')
        target_dir = (
            onedrive_p
            if os.path.exists(os.path.join(user_home, 'OneDrive'))
            else standard_p
        )

      os.makedirs(target_dir, exist_ok=True)

      timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
      backup_folder = os.path.join(target_dir, f'3R_Clinic_Backup_{timestamp}')
      os.makedirs(backup_folder, exist_ok=True)

      current_db = get_db_path()
      if os.path.exists(current_db):
        shutil.copy2(
            current_db, os.path.join(backup_folder, 'clinic_backup.db')
        )

      if os.path.exists(PATIENTS_ATTACHMENTS_DIR):
        shutil.copytree(
            PATIENTS_ATTACHMENTS_DIR,
            os.path.join(backup_folder, 'Patient_Attachments'),
            dirs_exist_ok=True,
        )

      return {
          'status': 'success',
          'path': backup_folder,
          'message': (
              f'تم إنشاء النسخة الاحتياطية بنجاح داخل:\n{backup_folder}'
          ),
      }
    except Exception as e:
      return {
          'status': 'error',
          'message': f'فشل إجراء النسخ الاحتياطي: {str(e)}',
      }

  def get_patients_list(self):
    with get_db() as conn:
      cursor = conn.cursor()
      cursor.execute('SELECT * FROM patients ORDER BY id DESC')
      return [dict(r) for r in cursor.fetchall()]

  def get_patient_by_id(self, p_id):
    with get_db() as conn:
      cursor = conn.cursor()
      cursor.execute('SELECT * FROM patients WHERE id=?', (int(p_id),))
      row = cursor.fetchone()
      return dict(row) if row else {}

  def open_patient_folder(self, p_id):
    with get_db() as conn:
      cursor = conn.cursor()
      cursor.execute('SELECT code, name FROM patients WHERE id=?', (int(p_id),))
      row = cursor.fetchone()

      if row:
        safe_name = ''.join([
            c for c in row['name'] if c.isalnum() or c in (' ', '_', '-')
        ]).rstrip()
        folder_name = f"{row['code'] or p_id}_{safe_name}"
        p_folder = os.path.join(PATIENTS_ATTACHMENTS_DIR, folder_name)
        os.makedirs(p_folder, exist_ok=True)

        cursor.execute(
            'UPDATE patients SET local_folder=? WHERE id=?',
            (p_folder, int(p_id)),
        )
        conn.commit()
        open_file_or_folder(p_folder)
        return {'status': 'success', 'path': p_folder}
    return {'status': 'error'}

  def suggest_patient_code(self):
    with get_db() as conn:
      return _next_patient_code(conn.cursor())

  def save_patient(self, data):
    with get_db() as conn:
      cursor = conn.cursor()
      p_id = data.get('id')

      is_new = not (p_id and str(p_id).isdigit())
      action = 'add' if is_new else 'edit'
      if not _role_allows(self._current_role, action):
        logger.warning(
            'Permission denied: user=%s role=%s action=%s',
            self._current_user, self._current_role, action,
        )
        return {
            'status': 'error',
            'message': PERMISSION_DENIED_MESSAGES[action],
        }

      # كود المريض: إجباري عند التسجيل لأول مرة، وغير مكرر دائماً
      code = str(data.get('code') or '').strip()
      if is_new and not code:
        return {
            'status': 'error',
            'message': 'كود المريض مطلوب. تم اقتراح الكود التالي، يمكنك تعديله.',
            'suggested_code': _next_patient_code(cursor),
        }
      if code:
        exclude_id = -1 if is_new else int(p_id)
        cursor.execute(
            'SELECT 1 FROM patients WHERE UPPER(TRIM(code))=? AND id<>?',
            (code.upper(), exclude_id),
        )
        if cursor.fetchone():
          return {
              'status': 'error',
              'message': f'الكود {code} مستخدم بالفعل لمريض آخر. تم اقتراح كود جديد.',
              'suggested_code': _next_patient_code(cursor),
          }
      data = {**data, 'code': code}

      fields = [
          'code',
          'name',
          'dob',
          'age',
          'residence',
          'contact',
          'date_of_visit',
          'local_folder',
          'chief_complaint',
          'onset',
          'duration',
          'severity',
          'frequency',
          'progression',
          'alleviating_factors',
          'aggravating_factors',
          'other_systems',
          'sym_syncope',
          'sym_palpitations',
          'sym_chest_pain',
          'sym_dyspnea',
          'sym_orthopnea',
          'sym_edema',
          'sym_low_cop',
          'sym_cyanosis',
          'past_medical',
          'past_surgical',
          'hospitalizations',
          'dev_delay',
          'medications',
          'natal_events',
          'allergies',
          'consanguinity',
          'scd',
          'family_history',
          'ecg',
          'holter',
          'echo',
          'inv_other',
          'lab_hb',
          'lab_tlc',
          'lab_plt',
          'lab_t3',
          'lab_t4',
          'lab_tsh',
          'lab_na',
          'lab_k',
          'lab_mg',
          'lab_hpylori',
          'lab_other',
          'lab_compliance',
          'diagnosis',
          'treatment',
          'plan',
          'status',
      ]
      values = [data.get(f, '') for f in fields]

      if p_id and str(p_id).isdigit():
        set_clause = ', '.join([f'{f}=?' for f in fields])
        cursor.execute(
            f'UPDATE patients SET {set_clause} WHERE id=?', values + [int(p_id)]
        )
      else:
        cols = ', '.join(fields)
        placeholders = ', '.join(['?'] * len(fields))
        cursor.execute(
            f'INSERT INTO patients ({cols}) VALUES ({placeholders})', values
        )

      _bump_patient_code_seq(cursor, code)
      conn.commit()
      return {'status': 'success'}

  @_requires_permission('delete')
  def delete_patient(self, p_id):
    with get_db() as conn:
      cursor = conn.cursor()
      cursor.execute('DELETE FROM patients WHERE id=?', (int(p_id),))
      cursor.execute('DELETE FROM followups WHERE patient_id=?', (int(p_id),))
      conn.commit()
      return {'status': 'success'}

  def get_followups(self, p_id):
    with get_db() as conn:
      cursor = conn.cursor()
      cursor.execute(
          'SELECT * FROM followups WHERE patient_id=? ORDER BY id DESC',
          (int(p_id),),
      )
      return [dict(r) for r in cursor.fetchall()]

  @_requires_permission('followup')
  def add_followup(self, data):
    with get_db() as conn:
      cursor = conn.cursor()
      cursor.execute(
          '''
                INSERT INTO followups (patient_id, visit_date, reason, plan_change, weight_bsa)
                VALUES (?, ?, ?, ?, ?)
            ''',
          (
              int(data['patient_id']),
              data.get('visit_date', ''),
              data.get('reason', ''),
              data.get('plan_change', ''),
              data.get('weight_bsa', ''),
          ),
      )
      conn.commit()
      return {'status': 'success'}

  def generate_research_report(self, patient_ids=None):
    with get_db() as conn:
      cursor = conn.cursor()
      if patient_ids and len(patient_ids) > 0:
        placeholders = ','.join(['?'] * len(patient_ids))
        cursor.execute(
            f'SELECT * FROM patients WHERE id IN ({placeholders})',
            [int(x) for x in patient_ids],
        )
      else:
        cursor.execute('SELECT * FROM patients')

      rows = [dict(r) for r in cursor.fetchall()]

    total = len(rows)
    if total == 0:
      return {'status': 'empty'}

    def _is_positive(value):
      # يحدد هل القيمة 'إيجابية' فعلاً، مش أي نص فيه رقم 1 بالصدفة (زي تاريخ أو عمر).
      # يقبل: 1 / true / yes / نعم / +ve / positive، كقيمة كاملة بعد التنظيف فقط.
      normalized = str(value or '').strip().lower()
      return normalized in ('1', 'true', 'yes', 'نعم', '+ve', 'positive')

    syncope_cnt = sum(
        1
        for r in rows
        if str(r.get('sym_syncope')) == '1'
        or 'syncope' in str(r.get('chief_complaint', '')).lower()
    )
    palp_cnt = sum(1 for r in rows if str(r.get('sym_palpitations')) == '1')
    chest_cnt = sum(1 for r in rows if str(r.get('sym_chest_pain')) == '1')
    dyspnea_cnt = sum(1 for r in rows if str(r.get('sym_dyspnea')) == '1')
    consang_cnt = sum(1 for r in rows if _is_positive(r.get('consanguinity')))
    scd_cnt = sum(1 for r in rows if _is_positive(r.get('scd')))
    ep_cnt = sum(
        1
        for r in rows
        if 'قسطرة' in str(r.get('status', ''))
        or 'ablation' in str(r.get('plan', '')).lower()
    )
    pm_cnt = sum(
        1
        for r in rows
        if 'منظم' in str(r.get('status', ''))
        or 'pacemaker' in str(r.get('plan', '')).lower()
    )

    scope_title = (
        f'تحليل عينة محددة ({total} مريض)'
        if patient_ids and len(patient_ids) > 0
        else f'تحليل كلي شامل ({total} مريض)'
    )

    report_html = f"""
        <div class="excel-sheet-container" style="border:2px solid #000; padding:15px; background:#fff; direction:rtl; font-family:'Segoe UI', Tahoma;">
            <div class="excel-header" style="background:#115173; color:white; font-weight:bold; padding:8px; text-align:center; font-size:15px; border:1px solid #000; margin-bottom:12px;">
                Pediatric Arrhythmia Research Report - [{scope_title}]
            </div>
            
            <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:10px; margin-bottom:15px;">
                <div style="border:1px solid #000; background:#f0f4f8; padding:10px; text-align:center; border-radius:4px;">
                    <div style="font-size:12px; font-weight:bold; color:#115173;">إجمالي عدد المرضى في التقرير</div>
                    <div style="font-size:24px; font-weight:bold; color:#022c43;">{total}</div>
                </div>
                <div style="border:1px solid #000; background:#fff3cd; padding:10px; text-align:center; border-radius:4px;">
                    <div style="font-size:12px; font-weight:bold; color:#856404;">حالات القسطرة والكي (EP & Ablation)</div>
                    <div style="font-size:24px; font-weight:bold; color:#856404;">{ep_cnt}</div>
                </div>
                <div style="border:1px solid #000; background:#f8d7da; padding:10px; text-align:center; border-radius:4px;">
                    <div style="font-size:12px; font-weight:bold; color:#721c24;">حالات منظم ضربات القلب (Pacemaker)</div>
                    <div style="font-size:24px; font-weight:bold; color:#721c24;">{pm_cnt}</div>
                </div>
            </div>

            <div style="border:1px solid #000; padding:10px; margin-bottom:12px; background:#fafafa;">
                <div style="font-weight:bold; color:#022c43; text-decoration:underline; margin-bottom:8px;">1. تحليل الأعراض المصاحبة والشكوى الرئيسية (Clinical Symptoms Analysis)</div>
                <table style="width:100%; border-collapse:collapse; font-size:12px;" border="1">
                    <tr style="background:#e9ecef;">
                        <th style="padding:6px;">العرض الطبي (Symptom)</th>
                        <th style="padding:6px; text-align:center;">عدد الحالات الإيجابية (1 / ✓)</th>
                        <th style="padding:6px; text-align:center;">النسبة المئوية (%)</th>
                    </tr>
                    <tr><td style="padding:5px;">الإغماء المتكرر (Syncope)</td><td style="text-align:center;">{syncope_cnt}</td><td style="text-align:center;">{(syncope_cnt/total)*100 if total else 0:.1f}%</td></tr>
                    <tr><td style="padding:5px;">الخفقان (Palpitations)</td><td style="text-align:center;">{palp_cnt}</td><td style="text-align:center;">{(palp_cnt/total)*100 if total else 0:.1f}%</td></tr>
                    <tr><td style="padding:5px;">آلام الصدر (Chest Pain)</td><td style="text-align:center;">{chest_cnt}</td><td style="text-align:center;">{(chest_cnt/total)*100 if total else 0:.1f}%</td></tr>
                    <tr><td style="padding:5px;">ضيق التنفس (Dyspnea)</td><td style="text-align:center;">{dyspnea_cnt}</td><td style="text-align:center;">{(dyspnea_cnt/total)*100 if total else 0:.1f}%</td></tr>
                </table>
            </div>

            <div style="border:1px solid #000; padding:10px; background:#fafafa;">
                <div style="font-weight:bold; color:#022c43; text-decoration:underline; margin-bottom:8px;">2. التاريخ العائلي والعوامل الوراثية (Family History & Risk Factors)</div>
                <table style="width:100%; border-collapse:collapse; font-size:12px;" border="1">
                    <tr style="background:#e9ecef;">
                        <th style="padding:6px;">العامل الوراثي / العائلي</th>
                        <th style="padding:6px; text-align:center;">عدد الحالات</th>
                        <th style="padding:6px; text-align:center;">النسبة المئوية (%)</th>
                    </tr>
                    <tr><td style="padding:5px;">صلة القرابة بين الوالدين (Consanguinity)</td><td style="text-align:center;">{consang_cnt}</td><td style="text-align:center;">{(consang_cnt/total)*100 if total else 0:.1f}%</td></tr>
                    <tr><td style="padding:5px;">تاريخ عائلي للوفاة المفاجئة (Sudden Cardiac Death - SCD)</td><td style="text-align:center;">{scd_cnt}</td><td style="text-align:center;">{(scd_cnt/total)*100 if total else 0:.1f}%</td></tr>
                </table>
            </div>
        </div>
        """
    return {'status': 'success', 'html': report_html}

  @_requires_permission('export')
  def export_excel(self, patient_ids=None):
    try:
      with get_db() as conn:
        cursor = conn.cursor()
        if patient_ids and len(patient_ids) > 0:
          placeholders = ','.join(['?'] * len(patient_ids))
          cursor.execute(
              f'SELECT * FROM patients WHERE id IN ({placeholders})',
              [int(x) for x in patient_ids],
          )
        else:
          cursor.execute('SELECT * FROM patients')
        rows = cursor.fetchall()
        headers = [description[0] for description in cursor.description]

      timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
      desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')
      os.makedirs(desktop_path, exist_ok=True)
      filename_prefix = (
          'Selected_Patients_Export'
          if patient_ids and len(patient_ids) > 0
          else 'Pediatric_Arrhythmia_Database'
      )
      file_path = os.path.join(
          desktop_path, f'{filename_prefix}_{timestamp}.csv'
      )

      with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

      open_file_or_folder(file_path)
      return {'status': 'success', 'path': file_path}
    except Exception as e:
      return {'status': 'error', 'message': str(e)}

  @_requires_permission('export')
  def export_single_patient_excel(self, p_id):
    try:
      p = self.get_patient_by_id(p_id)
      if not p:
        return {'status': 'error', 'message': 'لم يتم العثور على المريض'}

      timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
      desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')
      os.makedirs(desktop_path, exist_ok=True)
      file_path = os.path.join(
          desktop_path, f"Patient_Report_{p.get('code','000')}_{timestamp}.csv"
      )

      with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(['الحقل / Field', 'البيانات المسجلة / Record Value'])
        for k, v in p.items():
          writer.writerow([k, v])

      open_file_or_folder(file_path)
      return {'status': 'success', 'path': file_path}
    except Exception as e:
      return {'status': 'error', 'message': str(e)}

  @_requires_permission('manage_users')
  def get_users(self):
    with get_db() as conn:
      cursor = conn.cursor()
      cursor.execute('SELECT id, username, role FROM users ORDER BY id DESC')
      return [dict(r) for r in cursor.fetchall()]

  @_requires_permission('manage_users')
  def add_user(self, username, password, role):
    # لو مش Admin، يقدر بس يضيف حسابات Staff، عشان محدش يرفّع نفسه
    # أو حد تاني لدور Admin أو Doctor من غير ما يكون هو نفسه Admin.
    if self._current_role != 'Admin' and role != 'Staff':
      return {
          'status': 'error',
          'message': 'بس مدير النظام (Admin) يقدر يضيف حساب بدور غير Staff',
      }
    with get_db() as conn:
      cursor = conn.cursor()
      try:
        hashed = hash_password_new(password)
        cursor.execute(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            (username, hashed, role),
        )
        conn.commit()
        return {'status': 'success'}
      except Exception:
        return {'status': 'error', 'message': 'اسم المستخدم موجود بالفعل'}

  @_requires_permission('manage_users')
  def delete_user(self, u_id):
    with get_db() as conn:
      cursor = conn.cursor()
      cursor.execute('SELECT role FROM users WHERE id=?', (int(u_id),))
      row = cursor.fetchone()
      if not row:
        return {'status': 'error', 'message': 'المستخدم غير موجود'}
      if row['role'] == 'Admin':
        admin_count = conn.execute(
            "SELECT COUNT(*) FROM users WHERE role='Admin'"
        ).fetchone()[0]
        if admin_count <= 1:
          return {
              'status': 'error',
              'message': 'لا يمكن حذف آخر حساب Admin في النظام',
          }
      if self._current_role != 'Admin' and row['role'] != 'Staff':
        return {
            'status': 'error',
            'message': 'بس مدير النظام (Admin) يقدر يحذف حساب بدور غير Staff',
        }
      cursor.execute('DELETE FROM users WHERE id=?', (int(u_id),))
      conn.commit()
      return {'status': 'success'}

  @_requires_permission('manage_users')
  def update_user(self, u_id, new_role=None, new_password=None):
    """تعديل حساب موجود (الدور و/أو الباسورد) من غير حذفه وإعادة إنشائه."""
    u_id = int(u_id)
    with get_db() as conn:
      cursor = conn.cursor()
      cursor.execute('SELECT username, role FROM users WHERE id=?', (u_id,))
      row = cursor.fetchone()
      if not row:
        return {'status': 'error', 'message': 'المستخدم غير موجود'}

      target_role = new_role or row['role']

      # نفس قاعدة منع الترقية الذاتية: غير الـ Admin يقدر بس يلمس حسابات
      # Staff (لا يعدّل حساب Admin/Doctor، ولا يرقّي حد لدور أعلى من Staff).
      if self._current_role != 'Admin':
        if row['role'] != 'Staff' or target_role != 'Staff':
          return {
              'status': 'error',
              'message': 'بس مدير النظام (Admin) يقدر يعدّل حساب بدور غير Staff',
          }

      # منع حذف آخر Admin عن طريق تنزيل دوره
      if row['role'] == 'Admin' and target_role != 'Admin':
        admin_count = conn.execute(
            "SELECT COUNT(*) FROM users WHERE role='Admin'"
        ).fetchone()[0]
        if admin_count <= 1:
          return {
              'status': 'error',
              'message': 'لا يمكن تغيير دور آخر حساب Admin في النظام',
          }

      if new_role:
        cursor.execute('UPDATE users SET role=? WHERE id=?', (new_role, u_id))
      if new_password:
        if len(new_password) < 6:
          return {
              'status': 'error',
              'message': 'كلمة السر الجديدة يجب ألا تقل عن 6 خانات',
          }
        cursor.execute(
            'UPDATE users SET password=? WHERE id=?',
            (hash_password_new(new_password), u_id),
        )
      conn.commit()
      logger.info(
          'User updated: id=%s by=%s new_role=%s password_changed=%s',
          u_id, self._current_user, new_role or '-', bool(new_password),
      )
      return {'status': 'success'}

  def _require_admin(self):
    return self._current_role == 'Admin'

  def get_role_permissions(self):
    """قراءة صلاحيات كل دور. متاحة لأي حساب يدير مستخدمين، عشان تظهر
    الصلاحيات الحالية، لكن التعديل نفسه مقصور على Admin (تحت)."""
    if not _role_allows(self._current_role, 'manage_users'):
      return {'status': 'error', 'message': 'غير مسموح'}
    with get_db() as conn:
      rows = conn.execute('SELECT * FROM role_permissions').fetchall()
      return {'status': 'success', 'roles': [dict(r) for r in rows]}

  def update_role_permissions(self, role, perms):
    """تعديل صلاحيات دور معيّن. مقصور على Admin فقط، ومحظور لمس دور Admin نفسه."""
    if not self._require_admin():
      return {
          'status': 'error',
          'message': 'بس مدير النظام (Admin) يقدر يغيّر الصلاحيات',
      }
    if role not in ('Doctor', 'Staff'):
      return {'status': 'error', 'message': 'دور غير معروف'}
    columns = list(ACTION_TO_COLUMN.values())
    values = [1 if perms.get(c) else 0 for c in columns]
    with get_db() as conn:
      set_clause = ', '.join(f'{c}=?' for c in columns)
      conn.execute(
          f'UPDATE role_permissions SET {set_clause} WHERE role=?',
          values + [role],
      )
      conn.commit()
    logger.info('Role permissions updated for role=%s by %s', role, self._current_user)
    return {'status': 'success'}

  def get_my_permissions(self):
    """الصلاحيات الفعلية للمستخدم الحالي، عشان الواجهة تظهر/تخفي الأزرار بدقة."""
    role = self._current_role
    result = {'role': role}
    for action in ACTION_TO_COLUMN:
      result[action] = _role_allows(role, action)
    return result

  # -----------------------------------------------------------
  # وضع الصيانة (استرجاع الدخول بدون إنترنت)
  # خطوات الاستخدام: عايز تفعيل الشرح في ملف الدعم المرفق
  # -----------------------------------------------------------
  def list_admin_usernames(self):
    with get_db() as conn:
      rows = conn.execute(
          "SELECT username FROM users WHERE role='Admin' ORDER BY username"
      ).fetchall()
      return [r['username'] for r in rows]

  def get_recovery_challenge(self, username):
    with get_db() as conn:
      row = conn.execute(
          'SELECT id FROM users WHERE username=?', (username,)
      ).fetchone()
      if not row:
        return {'status': 'error', 'message': 'اسم المستخدم غير موجود'}
    challenge = f'{username}:{secrets.token_hex(6)}'
    if not hasattr(self, '_recovery_challenges'):
      self._recovery_challenges = {}
    self._recovery_challenges[username] = challenge
    return {'status': 'success', 'challenge': challenge}

  def redeem_recovery_code(self, username, signature_hex, new_password):
    challenge = getattr(self, '_recovery_challenges', {}).get(username)
    if not challenge:
      return {
          'status': 'error',
          'message': 'لازم تطلب كود التحقق الأول قبل إدخال كود الفتح',
      }
    if len(new_password or '') < 6:
      return {
          'status': 'error',
          'message': 'كلمة السر الجديدة يجب ألا تقل عن 6 خانات',
      }
    if not _verify_master_signature(challenge, (signature_hex or '').strip()):
      logger.warning('Failed maintenance recovery attempt for user=%s', username)
      return {'status': 'error', 'message': 'كود الفتح غير صحيح'}
    with get_db() as conn:
      conn.execute(
          'UPDATE users SET password=? WHERE username=?',
          (hash_password_new(new_password), username),
      )
      conn.commit()
    self._recovery_challenges.pop(username, None)
    logger.info('Password reset via maintenance mode for user=%s', username)
    return {'status': 'success'}


# ---------------------------------------------------------
# تسجيل عمليات الـ API تلقائياً (بدون تغيير سلوك أي دالة)
# ---------------------------------------------------------
AUDITED_ACTIONS = {
    'save_patient',
    'delete_patient',
    'add_followup',
    'add_user',
    'delete_user',
    'save_server_config',
    'execute_backup_now',
    'export_excel',
    'export_single_patient_excel',
}
ID_LOGGED_ACTIONS = {'delete_patient', 'delete_user'}


def _logged(fn):
  name = fn.__name__

  @functools.wraps(fn)
  def wrapper(self, *args, **kwargs):
    start = time.perf_counter()
    try:
      result = fn(self, *args, **kwargs)
    except Exception:
      logger.exception('API error in %s', name)
      raise

    elapsed = time.perf_counter() - start
    status = result.get('status') if isinstance(result, dict) else None

    if name == 'login_user':
      user = args[0] if args else kwargs.get('username', '')
      level = logging.INFO if status == 'success' else logging.WARNING
      logger.log(level, 'login_user user=%s result=%s', user, status)
    elif status == 'error':
      logger.warning('%s returned error: %s', name, result.get('message', ''))
    elif name in AUDITED_ACTIONS:
      detail = ''
      if name in ID_LOGGED_ACTIONS and args:
        detail = f' id={args[0]}'
      logger.info('action=%s%s', name, detail)

    if elapsed > 2:
      logger.warning('Slow API call: %s took %.1fs', name, elapsed)
    return result

  return wrapper


for _name, _member in list(vars(ClinicAPI).items()):
  if callable(_member) and not _name.startswith('_'):
    setattr(ClinicAPI, _name, _logged(_member))


# ---------------------------------------------------------
# بناء واجهة المستخدم HTML/CSS/JavaScript الكاملة
# ---------------------------------------------------------
def build_html_page():
  logo_src = get_logo_base64()
  logo_html = (
      f'<img src="{logo_src}" style="max-width:80px; max-height:80px;'
      ' margin-bottom:5px;">'
      if logo_src
      else """
        <svg width="65" height="65" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="46" fill="#ffffff" stroke="#00d2d3" stroke-width="3"/>
            <circle cx="50" cy="50" r="40" fill="#022c43" />
            <text x="50" y="58" font-family="Segoe UI, Arial" font-size="30" font-weight="bold" fill="#00d2d3" text-anchor="middle">3R</text>
        </svg>
    """
  )

  return f"""
<!DOCTYPE html>
<html lang="ar" dir="rtl" id="htmlRoot">
<head>
    <meta charset="UTF-8">
    <style>
        * {{ box-sizing: border-box; font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; padding: 0; }}
        body {{ display: flex; height: 100vh; background-color: #f4f6f9; overflow: hidden; }}
        
        #loginOverlay {{
            position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
            background: linear-gradient(135deg, #022c43 0%, #115173 100%);
            z-index: 99999; display: flex; justify-content: center; align-items: center;
        }}
        .login-card {{
            background: #ffffff; width: 420px; padding: 35px 30px; border-radius: 12px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.3); text-align: center; border-top: 5px solid #00d2d3;
        }}
        .login-card h2 {{ color: #022c43; font-size: 20px; margin-bottom: 5px; }}
        .login-card p {{ color: #666; font-size: 13px; margin-bottom: 25px; font-weight: bold; }}
        .login-group {{ text-align: right; margin-bottom: 18px; }}
        .login-group label {{ display: block; font-size: 12px; font-weight: bold; color: #115173; margin-bottom: 6px; }}
        .login-group input {{
            width: 100%; padding: 10px 12px; border: 1px solid #ccc; border-radius: 6px; font-size: 13px;
            outline: none; transition: 0.2s;
        }}
        .login-group input:focus {{ border-color: #00d2d3; box-shadow: 0 0 5px rgba(0,210,211,0.4); }}
        .login-btn-submit {{
            width: 100%; background: #022c43; color: white; border: none; padding: 12px; border-radius: 6px;
            font-size: 14px; font-weight: bold; cursor: pointer; transition: 0.2s; margin-top: 10px;
        }}
        .login-btn-submit:hover {{ background: #00d2d3; color: #022c43; }}
        .login-error {{ color: #e74c3c; font-size: 12px; margin-top: 12px; font-weight: bold; display: none; }}

        .sidebar {{ width: 270px; background: #022c43; color: white; padding: 15px 10px; display: flex; flex-direction: column; gap: 10px; }}
        .logo-box {{ text-align: center; margin-bottom: 10px; padding-bottom: 10px; border-bottom: 1px solid #115173; }}
        .logo-box h2 {{ font-size: 15px; color: #00d2d3; margin-top: 5px; }}
        .logo-box p {{ font-size: 11px; color: #c8d6e5; font-weight: bold; }}
        
        .side-section-title {{ font-size: 12px; font-weight: bold; color: #00d2d3; margin-top: 5px; margin-bottom: 3px; padding-right: 5px; }}
        
        .side-btn {{ background: #115173; border: 1px solid #00d2d3; color: white; padding: 10px; text-align: right; width: 100%; font-size: 12px; font-weight: bold; border-radius: 6px; cursor: pointer; transition: 0.2s; display: flex; align-items: center; justify-content: flex-start; gap: 8px; }}
        .side-btn:hover {{ background: #00d2d3; color: #022c43; }}
        .side-btn.accent {{ background: #05b46a; border-color: #05b46a; }}
        .side-btn.accent:hover {{ background: #048a51; }}
        
        .main-content {{ flex: 1; padding: 20px; overflow-y: auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; background: white; padding: 12px 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); margin-bottom: 15px; }}
        
        .selected-banner {{ background: #e3f2fd; border: 1px solid #90caf9; padding: 8px 12px; border-radius: 6px; margin-bottom: 12px; font-size: 13px; color: #0d47a1; display: flex; justify-content: space-between; align-items: center; }}
        
        .btn-act {{ border: none; padding: 5px 8px; border-radius: 4px; cursor: pointer; font-size: 11px; font-weight: bold; margin-left: 2px; }}
        .btn-edit {{ background: #ff9f43; color: white; }}
        .btn-print {{ background: #54a0ff; color: white; }}
        .btn-follow {{ background: #9b59b6; color: white; }}
        .btn-folder {{ background: #107c41; color: white; }}
        .btn-delete {{ background: #ee5253; color: white; }}
        
        .search-box {{ padding: 8px 12px; width: 280px; border: 1px solid #ccc; border-radius: 5px; font-size: 13px; }}
        table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }}
        th, td {{ padding: 9px 11px; text-align: right; border-bottom: 1px solid #eee; font-size: 12px; }}
        th {{ background: #115173; color: white; }}
        tr.selected-row {{ background-color: #fff9c4 !important; }}
        
        .modal {{ display: none; position: fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.6); justify-content:center; align-items:center; z-index:10000; }}
        .modal-content {{ background: white; padding: 20px; border-radius: 8px; width: 920px; max-height: 94vh; overflow-y: auto; border: 3px solid #022c43; }}
        
        .excel-sheet-container {{ border: 2px solid #000; padding: 10px; background: #fff; font-size: 12px; }}
        .excel-header {{ background: #115173; color: white; font-weight: bold; padding: 6px 10px; margin-bottom: 8px; font-size: 13px; text-align: center; border: 1px solid #000; }}
        .excel-section {{ border: 1px solid #000; padding: 8px; margin-bottom: 8px; background: #fafafa; }}
        .excel-section-title {{ font-weight: bold; color: #022c43; text-decoration: underline; margin-bottom: 6px; font-size: 12px; }}
        
        .excel-grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }}
        .excel-grid-3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; }}
        
        .field-box {{ display: flex; align-items: center; gap: 5px; margin-bottom: 4px; }}
        .field-box label {{ font-size: 11px; font-weight: bold; color: #115173; min-width: 90px; }}
        .field-box input, .field-box select {{ flex: 1; padding: 5px 8px; border: 1px solid #777; font-size: 12px; background: #fff; border-radius: 4px; }}
        
        .check-table {{ width: 100%; border-collapse: collapse; margin-top: 4px; }}
        .check-table td {{ border: 1px solid #999; padding: 3px 6px; font-size: 11px; text-align: center; }}
        
        .user-badge {{ background: #00d2d3; color: #022c43; padding: 4px 10px; border-radius: 20px; font-weight: bold; font-size: 12px; }}
    </style>
</head>
<body>

    <div id="loginOverlay">
        <div class="login-card" id="loginCard">
            {logo_html}
            <h2>3R Clinic System</h2>
            <p>تسجيل الدخول للنظام</p>

            <div class="login-group">
                <label>اسم المستخدم (Username):</label>
                <input type="text" id="loginUsername" placeholder="ادخل اسم المستخدم..." onkeypress="if(event.key==='Enter') executeLogin()">
            </div>

            <div class="login-group">
                <label>كلمة السر (Password):</label>
                <input type="password" id="loginPassword" placeholder="ادخل كلمة السر..." onkeypress="if(event.key==='Enter') executeLogin()">
            </div>

            <div style="text-align:right; margin-bottom:15px; font-size:12px;">
                <input type="checkbox" id="showPassCb" onclick="togglePassVisibility()"> <label for="showPassCb" style="color:#555; cursor:pointer;">إظهار كلمة السر</label>
            </div>

            <button class="login-btn-submit" onclick="executeLogin()">تسجيل الدخول 🔓</button>
            <div id="loginErrorMsg" class="login-error">اسم المستخدم أو كلمة السر غير صحيحة</div>
            <div style="text-align:center; margin-top:12px;">
                <a href="#" style="font-size:12px; color:#115173;" onclick="openRecoveryModal(); return false;">نسيت كلمة السر؟ / وضع الصيانة</a>
            </div>
        </div>

        <div class="login-card" id="setupCard" style="display:none;">
            {logo_html}
            <h2>3R Clinic System</h2>
            <p>أول تشغيل: من فضلك أنشئ حساب المدير (Admin) الخاص بالعيادة</p>

            <div class="login-group">
                <label>اسم المستخدم الجديد:</label>
                <input type="text" id="setupUsername" placeholder="مثال: admin">
            </div>
            <div class="login-group">
                <label>كلمة السر (6 خانات على الأقل):</label>
                <input type="password" id="setupPassword" placeholder="كلمة سر قوية">
            </div>
            <div class="login-group">
                <label>تأكيد كلمة السر:</label>
                <input type="password" id="setupPasswordConfirm" placeholder="أعد كتابة كلمة السر">
            </div>
            <button class="login-btn-submit" onclick="submitFirstAdmin()">إنشاء الحساب والدخول 🔒</button>
            <div id="setupErrorMsg" class="login-error"></div>
        </div>

        <div class="login-card" id="recoveryCard" style="display:none;">
            {logo_html}
            <h2>وضع الصيانة</h2>
            <p>لو نسيت كلمة السر، تواصل مع الدعم الفني وأعطهم البيانات دي</p>

            <div class="login-group">
                <label>اختر الحساب:</label>
                <select id="recoveryUsername" style="width:100%; padding:8px; border-radius:6px; border:1px solid #ccc;"></select>
            </div>
            <button class="login-btn-submit" onclick="requestRecoveryChallenge()">طلب كود التحقق</button>

            <div id="recoveryStep2" style="display:none; margin-top:15px; text-align:right;">
                <div class="login-group">
                    <label>كود التحقق (أرسله للدعم الفني):</label>
                    <input type="text" id="recoveryChallengeBox" readonly style="text-align:center; font-family:monospace; direction:ltr;">
                </div>
                <div class="login-group">
                    <label>كود الفتح (هيبعتهولك الدعم الفني):</label>
                    <input type="text" id="recoverySignature" placeholder="الصق كود الفتح هنا" style="direction:ltr;">
                </div>
                <div class="login-group">
                    <label>كلمة السر الجديدة:</label>
                    <input type="password" id="recoveryNewPassword" placeholder="كلمة سر جديدة (6 خانات على الأقل)">
                </div>
                <button class="login-btn-submit" onclick="submitRecoveryCode()">تغيير كلمة السر</button>
            </div>
            <div id="recoveryErrorMsg" class="login-error"></div>
            <div style="text-align:center; margin-top:12px;">
                <a href="#" style="font-size:12px; color:#115173;" onclick="closeRecoveryModal(); return false;">رجوع لتسجيل الدخول</a>
            </div>
        </div>
    </div>

    <div class="sidebar">
        <div class="logo-box">
            {logo_html}
            <h2>3R Software Solutions</h2>
            <p>3R Clinic System</p>
        </div>

        <div class="side-section-title" id="lblReportsSection">📌 أدوات التقارير والبحث:</div>
        <button class="side-btn" onclick="generateSelectedPatientReport()" id="btnReportSingle">📄 مولد تقرير المريض (المحدد بالشيت)</button>
        <button class="side-btn" onclick="generateResearchReport()" id="btnReportResearch">📊 تقرير الأريثما (للمرضى المحددين)</button>

        <div class="side-section-title" style="margin-top:10px;" id="lblFilesSection">📁 إدارة الملفات:</div>
        <button class="side-btn accent" onclick="openNewModal()" id="btnAddPatient">+ إضافة مريض جديد (واجهة الشيت)</button>
        <button class="side-btn" style="background:#107c41; border-color:#107c41;" onclick="exportExcel()" id="btnExportCSV">💾 تصدير قاعدة البيانات (Excel/CSV)</button>

        <div class="side-section-title" style="margin-top:10px;" id="lblSettingsSection">⚙️ النظام والإعدادات:</div>
        <button class="side-btn" style="background:#4b6584; border-color:#4b6584;" onclick="openSettingsModal()" id="btnSettings">⚙️ إعدادات السيرفر والنسخ الاحتياطي</button>
        
        <div style="display:flex; gap:5px; margin-top:auto;">
            <button class="side-btn" style="text-align:center; flex:1;" onclick="setLang('ar')">🇸🇦 عربي</button>
            <button class="side-btn" style="text-align:center; flex:1;" onclick="setLang('en')">🇬🇧 English</button>
        </div>
    </div>

    <div class="main-content">
        <div class="header">
            <h3 id="lblWelcome">مرحباً بك دكتور | 3R Software Solutions</h3>
            <div style="display:flex; align-items:center; gap:12px;">
                <div>
                    <span style="font-weight: bold; color: #115173; margin-left:5px;">المستخدم النشط:</span>
                    <span id="activeUserLabel" class="user-badge">-</span>
                </div>
                <button class="btn-act btn-delete" style="padding:6px 12px; font-size:12px;" onclick="logoutUser()">تسجيل الخروج 🔒</button>
            </div>
        </div>

        <div class="selected-banner">
            <span><span id="lblSelectedText">المريض المحدد حالياً:</span> <b id="selectedPatientName">حدد مريضاً بـ (✓) لإنشاء التقرير له</b></span>
            <input type="text" class="search-box" id="searchBox" placeholder="بحث باسم الطفل أو الكود..." onkeyup="filterPatients(this.value)">
        </div>

        <table>
            <thead>
                <tr>
                    <th style="width:30px; text-align:center;"><input type="checkbox" id="selectAllCb" onclick="toggleSelectAll(this)" title="تحديد/إلغاء تحديد الكل"></th>
                    <th id="thCode">الكود</th>
                    <th id="thName">اسم الطفل</th>
                    <th id="thAge">العمر</th>
                    <th id="thContact">الهاتف</th>
                    <th id="thComplaint">الشكوى الرئيسية</th>
                    <th id="thDiag">التشخيص (Diagnosis)</th>
                    <th id="thPlan">الخطة العلاجية</th>
                    <th id="thStatus">الحالة</th>
                    <th style="text-align:center;" id="thActions">الإجراءات والتحاليل</th>
                </tr>
            </thead>
            <tbody id="patientTable"></tbody>
        </table>
    </div>

    <div id="patientModal" class="modal">
        <div class="modal-content">
            <input type="hidden" id="p_id">
            <div class="excel-sheet-container">
                <div class="excel-header">Pediatric Arrhythmia Outpatient Clinic - Patient Form Sheet</div>
                
                <div class="excel-section">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                        <div class="excel-section-title">Demographic Information</div>
                        <button class="btn-act btn-folder" onclick="openCurrentPatientFolder()">📂 فتح مجلد مرفقات وتحاليل المريض</button>
                    </div>
                    <div class="excel-grid-3">
                        <div class="field-box"><label>Code (الكود): <span style="color:#dc3545;">*</span></label><input type="text" id="p_code" placeholder="P-01"></div>
                        <div class="field-box"><label>Name (الاسم):</label><input type="text" id="p_name"></div>
                        <div class="field-box"><label>Age (العمر):</label><input type="text" id="p_age"></div>
                        <div class="field-box"><label>Date of Birth:</label><input type="date" id="p_dob"></div>
                        <div class="field-box"><label>Residence:</label><input type="text" id="p_residence"></div>
                        <div class="field-box"><label>Contact:</label><input type="text" id="p_contact"></div>
                        <div class="field-box"><label>Date of Visit:</label><input type="date" id="p_date_of_visit"></div>
                        <div class="field-box" style="grid-column: span 2;"><label>Local Folder:</label><input type="text" id="p_local_folder" readonly placeholder="ينشأ تلقائياً عند إضافة المرفقات"></div>
                    </div>
                </div>

                <div class="excel-grid-2">
                    <div class="excel-section">
                        <div class="excel-section-title">History of Present Illness (HPI)</div>
                        <div class="field-box"><label>Chief Complaint:</label><input type="text" id="p_chief_complaint"></div>
                        <div class="field-box"><label>Onset:</label><input type="text" id="p_onset"></div>
                        <div class="field-box"><label>Duration:</label><input type="text" id="p_duration"></div>
                        <div class="field-box"><label>Frequency:</label><input type="text" id="p_frequency"></div>
                        <div class="field-box"><label>Severity:</label><input type="text" id="p_severity"></div>
                        <div class="field-box"><label>Progression:</label><input type="text" id="p_progression"></div>
                        <div class="field-box"><label>Alleviating:</label><input type="text" id="p_alleviating_factors"></div>
                        <div class="field-box"><label>Aggravating:</label><input type="text" id="p_aggravating_factors"></div>
                        <div class="field-box"><label>Other Systems:</label><input type="text" id="p_other_systems" value="0"></div>
                    </div>

                    <div class="excel-section">
                        <div class="excel-section-title">Associated Symptoms & Signs</div>
                        <table class="check-table">
                            <tr><td>Syncope</td><td><select id="p_sym_syncope"><option value="1">1 (✓)</option><option value="0">0 (X)</option></select></td></tr>
                            <tr><td>Palpitations</td><td><select id="p_sym_palpitations"><option value="1">1 (✓)</option><option value="0">0 (X)</option></select></td></tr>
                            <tr><td>Chest Pain</td><td><select id="p_sym_chest_pain"><option value="1">1 (✓)</option><option value="0">0 (X)</option></select></td></tr>
                            <tr><td>Dyspnea</td><td><select id="p_sym_dyspnea"><option value="1">1 (✓)</option><option value="0">0 (X)</option></select></td></tr>
                            <tr><td>Orthopnea</td><td><select id="p_sym_orthopnea"><option value="1">1 (✓)</option><option value="0">0 (X)</option></select></td></tr>
                            <tr><td>Edema</td><td><select id="p_sym_edema"><option value="1">1 (✓)</option><option value="0">0 (X)</option></select></td></tr>
                            <tr><td>Signs of Low COP</td><td><select id="p_sym_low_cop"><option value="1">1 (✓)</option><option value="0">0 (X)</option></select></td></tr>
                            <tr><td>Cyanosis</td><td><select id="p_sym_cyanosis"><option value="1">1 (✓)</option><option value="0">0 (X)</option></select></td></tr>
                        </table>
                    </div>
                </div>

                <div class="excel-grid-2">
                    <div class="excel-section">
                        <div class="excel-section-title">Past History & Family History</div>
                        <div class="field-box"><label>Past Medical:</label><input type="text" id="p_past_medical" value="NAD"></div>
                        <div class="field-box"><label>Past Surgical:</label><input type="text" id="p_past_surgical"></div>
                        <div class="field-box"><label>Hospitalizations:</label><input type="text" id="p_hospitalizations"></div>
                        <div class="field-box"><label>Dev. Delay:</label><input type="text" id="p_dev_delay" value="0"></div>
                        <div class="field-box"><label>Medications:</label><input type="text" id="p_medications"></div>
                        <div class="field-box"><label>Natal Events:</label><input type="text" id="p_natal_events" value="0"></div>
                        <div class="field-box"><label>Allergies:</label><input type="text" id="p_allergies" value="0"></div>
                        <hr style="margin:5px 0;">
                        <div class="field-box"><label>Consanguinity:</label><input type="text" id="p_consanguinity"></div>
                        <div class="field-box"><label>SCD (Sudden Death):</label><input type="text" id="p_scd"></div>
                        <div class="field-box"><label>Family History:</label><input type="text" id="p_family_history"></div>
                    </div>

                    <div class="excel-section">
                        <div class="excel-section-title">Investigations & Laboratory Panel</div>
                        <div class="field-box"><label>ECG:</label><input type="text" id="p_ecg"></div>
                        <div class="field-box"><label>Holter:</label><input type="text" id="p_holter"></div>
                        <div class="field-box"><label>Echo:</label><input type="text" id="p_echo"></div>
                        <div class="field-box"><label>Inv. Other:</label><input type="text" id="p_inv_other" value="0"></div>
                        <hr style="margin:5px 0;">
                        <div class="excel-grid-3">
                            <div class="field-box"><label>HB:</label><input type="text" id="p_lab_hb"></div>
                            <div class="field-box"><label>TLC:</label><input type="text" id="p_lab_tlc"></div>
                            <div class="field-box"><label>PLT:</label><input type="text" id="p_lab_plt"></div>
                            <div class="field-box"><label>T3:</label><input type="text" id="p_lab_t3"></div>
                            <div class="field-box"><label>T4:</label><input type="text" id="p_lab_t4"></div>
                            <div class="field-box"><label>TSH:</label><input type="text" id="p_lab_tsh"></div>
                            <div class="field-box"><label>Na:</label><input type="text" id="p_lab_na"></div>
                            <div class="field-box"><label>K:</label><input type="text" id="p_lab_k"></div>
                            <div class="field-box"><label>Mg:</label><input type="text" id="p_lab_mg"></div>
                        </div>
                    </div>
                </div>

                <div class="excel-section">
                    <div class="excel-section-title">Diagnosis & Plan of Management</div>
                    <div class="excel-grid-3">
                        <div class="field-box"><label>Diagnosis:</label><input type="text" id="p_diagnosis"></div>
                        <div class="field-box"><label>Treatment:</label><input type="text" id="p_treatment"></div>
                        <div class="field-box"><label>Plan of Mgmt:</label><input type="text" id="p_plan"></div>
                    </div>
                    <div class="field-box" style="margin-top:5px;">
                        <label>حالة الملف:</label>
                        <select id="p_status">
                            <option value="متابعة">متابعة العيادة الخارجية</option>
                            <option value="قسطرة تداخلية">قسطرة دراسات كهرولوجية وكي (EP Study & Ablation)</option>
                            <option value="تركيب منظم">تحويل لتركيب منظم ضربات قلب (Pacemaker)</option>
                            <option value="تم الشفاء">مستقر / تم الشفاء</option>
                        </select>
                    </div>
                </div>
            </div>

            <div style="display: flex; gap: 10px; margin-top: 15px;">
                <button class="btn" style="flex:1; padding:10px; background:#05b46a; color:white; border:none; border-radius:5px; font-weight:bold; cursor:pointer;" onclick="savePatient()">حفظ البيانات بالشيت</button>
                <button class="btn" style="flex:1; background:#dc3545; color:white; border:none; border-radius:5px; font-weight:bold; cursor:pointer;" onclick="closeModal()">إلغاء</button>
            </div>
        </div>
    </div>

    <div id="followupModal" class="modal">
        <div class="modal-content" style="width:750px;">
            <h3 style="color:#115173; margin-bottom:12px;" id="fuTitle">Follow up visits - جدول زيارات المتابعة</h3>
            <input type="hidden" id="fu_patient_id">
            
            <div style="background:#f8f9fa; padding:12px; border-radius:6px; margin-bottom:15px; border:1px solid #ddd;">
                <h4 style="font-size:13px; color:#115173; margin-bottom:8px;">+ تسجيل زيارة جديدة</h4>
                <div class="excel-grid-2">
                    <div class="field-box"><label>Date:</label><input type="date" id="fu_date"></div>
                    <div class="field-box"><label>Current wt / BSA:</label><input type="text" id="fu_weight" placeholder="38 كجم / 1.2 m²"></div>
                </div>
                <div class="field-box"><label>Reason for visiting:</label><input type="text" id="fu_reason"></div>
                <div class="field-box"><label>Change in plan:</label><input type="text" id="fu_plan_change"></div>
                <button class="btn" style="padding:6px 14px; margin-top:5px; font-size:12px; background:#05b46a; color:white; border:none; border-radius:4px; font-weight:bold; cursor:pointer;" onclick="saveFollowup()">إضافة الزيارة للشيت</button>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Reason for visiting</th>
                        <th>Change in plan</th>
                        <th>Current wt / BSA</th>
                    </tr>
                </thead>
                <tbody id="followupTable"></tbody>
            </table>

            <div style="text-align:left; margin-top:15px;">
                <button class="btn" style="background:#555; color:white; border:none; padding:8px 15px; border-radius:4px; cursor:pointer;" onclick="document.getElementById('followupModal').style.display='none'">إغلاق</button>
            </div>
        </div>
    </div>

    <div id="viewModal" class="modal">
        <div class="modal-content" style="width:880px;">
            <div id="viewBody"></div>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-top:15px;">
                <div>
                    <button class="btn" style="background:#107c41; color:white; border:none; padding:8px 15px; border-radius:4px; font-weight:bold; cursor:pointer;" onclick="exportCurrentReportExcel()">📊 تصدير لـ Excel</button>
                </div>
                <div>
                    <button class="btn" style="background:#115173; color:white; border:none; padding:8px 15px; border-radius:4px; cursor:pointer;" onclick="window.print()">🖨️ طباعة التقرير / PDF</button>
                    <button class="btn" style="background:#555; color:white; border:none; padding:8px 15px; border-radius:4px; margin-right:5px; cursor:pointer;" onclick="document.getElementById('viewModal').style.display='none'">إغلاق</button>
                </div>
            </div>
        </div>
    </div>

    <div id="settingsModal" class="modal">
        <div class="modal-content" style="width:800px;">
            <h3 style="color:#022c43; margin-bottom:12px; border-bottom:2px solid #00d2d3; padding-bottom:5px;">⚙️ إعدادات السيرفر، الشبكة والنسخ الاحتياطي (Backup)</h3>
            
            <div id="serverSettingsSection" style="background:#f0f4f8; border:1px solid #90caf9; padding:12px; border-radius:6px; margin-bottom:15px;">
                <h4 style="font-size:13px; color:#0d47a1; margin-bottom:8px;">🌐 1. إعدادات السيرفر وقاعدة البيانات (Server Connection Settings):</h4>
                <div style="margin-bottom:8px;">
                    <label style="font-weight:bold; font-size:12px; margin-left:10px;">وضع التشغيل:</label>
                    <input type="radio" id="mode_local" name="db_mode" value="local" onchange="toggleServerInputs()"> <label for="mode_local" style="font-size:12px; margin-left:15px;">جهاز محلي منفرد (Standalone Local)</label>
                    <input type="radio" id="mode_network" name="db_mode" value="network" onchange="toggleServerInputs()"> <label for="mode_network" style="font-size:12px;">ربط عبر شبكة داخلية (Network Shared DB)</label>
                </div>
                <div id="networkPathBox" class="field-box" style="margin-top:8px; display:none;">
                    <label style="min-width:160px; font-size:11px;">مسار ملف القاعدة على السيرفر:</label>
                    <input type="text" id="cfg_network_path" placeholder="مثال: \\192.168.1.100\ClinicData\clinic.db أو Z:\clinic.db">
                </div>
            </div>

            <div id="backupSettingsSection" style="background:#e8f5e9; border:1px solid #a5d6a7; padding:12px; border-radius:6px; margin-bottom:15px;">
                <h4 style="font-size:13px; color:#1b5e20; margin-bottom:8px;">💾 2. إعدادات النسخ الاحتياطي (Backup Settings):</h4>
                <div class="field-box">
                    <label style="min-width:160px; font-size:11px;">مجلد حفظ النسخ الاحتياطية:</label>
                    <input type="text" id="cfg_backup_path" placeholder="مثال: D:\Clinic_Backups أو مسار الفلاشة USB">
                </div>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-top:8px;">
                    <button class="btn" style="padding:7px 15px; font-size:12px; background:#2e7d32; color:white; border:none; border-radius:4px; font-weight:bold; cursor:pointer;" onclick="executeBackupNow()">💾 أخذ نسخة احتياطية فورية الآن</button>
                    <button class="btn" style="padding:7px 15px; font-size:12px; background:#05b46a; color:white; border:none; border-radius:4px; font-weight:bold; cursor:pointer;" onclick="saveServerSettings()">حفظ إعدادات السيرفر والنسخ الاحتياطي</button>
                </div>
            </div>

            <div id="usersSection" style="background:#fafafa; border:1px solid #ddd; padding:12px; border-radius:6px; margin-bottom:15px;">
                <h4 style="font-size:13px; color:#115173; margin-bottom:8px;">👥 3. إدارة المستخدمين:</h4>
                <div style="display:grid; grid-template-columns: 1fr 1fr 1fr 110px; gap:8px; align-items:center; margin-bottom:10px;">
                    <div class="field-box" style="margin:0;"><label style="min-width:50px;">الاسم:</label><input type="text" id="new_username"></div>
                    <div class="field-box" style="margin:0;"><label style="min-width:50px;">الرمز:</label><input type="password" id="new_password"></div>
                    <div class="field-box" style="margin:0;"><label style="min-width:40px;">الدور:</label>
                        <select id="new_role"></select>
                    </div>
                    <button class="btn" style="padding:6px; font-size:12px; background:#115173; color:white; border:none; border-radius:4px; font-weight:bold; cursor:pointer;" onclick="saveUser()">+ إضافة مستخدم</button>
                </div>

                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>اسم المستخدم</th>
                            <th>الصلاحية والRole</th>
                            <th style="text-align:center;">إجراء</th>
                        </tr>
                    </thead>
                    <tbody id="usersTable"></tbody>
                </table>
            </div>

            <div id="rolePermSection" style="background:#fff8e1; border:1px solid #ffe082; padding:12px; border-radius:6px;">
                <h4 style="font-size:13px; color:#8d6e00; margin-bottom:8px;">🔑 4. صلاحيات كل دور (Doctor / Staff):</h4>
                <p style="font-size:11px; color:#777; margin-bottom:10px;">حدد مقدماً أنهي عمليات مسموح بيها لكل دور. Admin دايماً عنده كل الصلاحيات ومينفعش تتغير.</p>
                <table id="rolePermTable" style="font-size:12px;">
                    <thead>
                        <tr>
                            <th style="text-align:right;">الدور</th>
                            <th>إضافة مريض</th>
                            <th>تعديل مريض</th>
                            <th>حذف مريض</th>
                            <th>متابعات</th>
                            <th>تصدير بيانات</th>
                            <th>إعدادات السيرفر</th>
                            <th>إدارة المستخدمين</th>
                            <th>حفظ</th>
                        </tr>
                    </thead>
                    <tbody id="rolePermTableBody"></tbody>
                </table>
            </div>

            <div style="text-align:left; margin-top:15px;">
                <button class="btn" style="background:#555; color:white; border:none; padding:8px 15px; border-radius:4px; cursor:pointer;" onclick="document.getElementById('settingsModal').style.display='none'">إغلاق</button>
            </div>
        </div>
    </div>

    <div id="editUserModal" class="modal">
        <div class="modal-content" style="width:380px;">
            <h3 style="color:#022c43; margin-bottom:15px; border-bottom:2px solid #00d2d3; padding-bottom:5px;">تعديل حساب: <span id="editUserLabel"></span></h3>

            <div class="field-box">
                <label style="min-width:90px;">الدور الجديد:</label>
                <select id="editUserRole"></select>
            </div>
            <div class="field-box">
                <label style="min-width:90px;">باسورد جديد:</label>
                <input type="password" id="editUserPassword" placeholder="اسيبها فاضية لو مش عايز تغيّرها">
            </div>

            <div style="display:flex; justify-content:space-between; margin-top:15px;">
                <button class="btn" style="background:#555; color:white; border:none; padding:8px 15px; border-radius:4px; cursor:pointer;" onclick="document.getElementById('editUserModal').style.display='none'">إلغاء</button>
                <button class="btn" style="background:#115173; color:white; border:none; padding:8px 15px; border-radius:4px; font-weight:bold; cursor:pointer;" onclick="submitEditUser()">حفظ التعديل</button>
            </div>
        </div>
    </div>

    <script>
        let selectedPatientId = null;
        let currentRole = null;
        let currentUsername = null;
        let currentReportPatientIds = [];

        let currentPermissions = {{}};

        function executeLogin() {{
            const u = document.getElementById('loginUsername').value.trim();
            const p = document.getElementById('loginPassword').value.trim();
            const errBox = document.getElementById('loginErrorMsg');

            if (!u || !p) {{
                errBox.innerText = 'يرجى إدخال اسم المستخدم وكلمة السر!';
                errBox.style.display = 'block';
                return;
            }}

            window.pywebview.api.login_user(u, p).then(res => {{
                if (res.status === 'success') {{
                    currentUsername = res.username;
                    currentRole = res.role;
                    document.getElementById('activeUserLabel').innerText = `${{currentUsername}} (${{currentRole}})`;
                    document.getElementById('loginOverlay').style.display = 'none';
                    errBox.style.display = 'none';
                    document.getElementById('loginPassword').value = '';
                    window.pywebview.api.get_my_permissions().then(perms => {{
                        currentPermissions = perms || {{}};
                        applyPermissionsToSidebar();
                        loadTableData();
                    }});
                }} else {{
                    errBox.innerText = res.message;
                    errBox.style.display = 'block';
                }}
            }});
        }}

        function applyPermissionsToSidebar() {{
            const canSeeSettings = checkPermission('settings') || checkPermission('manage_users');
            document.getElementById('btnSettings').style.display = canSeeSettings ? '' : 'none';
            document.getElementById('btnAddPatient').style.display = checkPermission('add') ? '' : 'none';
            document.getElementById('btnExportCSV').style.display = checkPermission('export') ? '' : 'none';
        }}

        function togglePassVisibility() {{
            const passInput = document.getElementById('loginPassword');
            const cb = document.getElementById('showPassCb');
            passInput.type = cb.checked ? 'text' : 'password';
        }}

        function logoutUser() {{
            window.pywebview.api.logout();
            currentUsername = null;
            currentRole = null;
            currentPermissions = {{}};
            document.getElementById('loginUsername').value = '';
            document.getElementById('loginPassword').value = '';
            document.getElementById('loginOverlay').style.display = 'flex';
        }}

        function checkPermission(action) {{
            if (currentRole === 'Admin') return true;
            if (action === 'view') return !!currentRole;
            return !!currentPermissions[action];
        }}

        function getCheckedPatientIds() {{
            const checkboxes = document.querySelectorAll('.patient-cb:checked');
            return Array.from(checkboxes).map(cb => cb.value);
        }}

        function toggleSelectAll(masterCb) {{
            const checkboxes = document.querySelectorAll('.patient-cb');
            checkboxes.forEach(cb => cb.checked = masterCb.checked);
            updateSelectedBanner();
        }}

        function updateSelectedBanner() {{
            const ids = getCheckedPatientIds();
            const banner = document.getElementById('selectedPatientName');
            if (ids.length === 0) {{
                banner.innerText = 'حدد مريضاً بـ (✓) لإنشاء التقرير له';
            }} else if (ids.length === 1) {{
                banner.innerText = `تم تحديد مريض واحد (ID: ${{ids[0]}})`;
            }} else {{
                banner.innerText = `تم تحديد عينة مكونة من (${{ids.length}}) مرضى للتقرير`;
            }}
        }}

        // تأمين أي نص قبل عرضه كـ HTML، عشان اسم مريض فيه علامات زي < أو "
        // أو ' ميبوظش الشاشة ولا ينفّذ كـ كود (XSS)
        function escapeHtml(str) {{
            if (str === null || str === undefined) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }}

        // نسخة مؤمّنة من بيانات المريض لعرضها كـ HTML (كل القيم النصية متأمّنة)
        function escapedPatient(p) {{
            const out = {{}};
            for (const k in p) {{
                out[k] = (typeof p[k] === 'string') ? escapeHtml(p[k]) : p[k];
            }}
            return out;
        }}

        // اسم كل مريض محفوظ هنا بالـ id، عشان أزرار الحذف/المتابعات تاخده من غير
        // ما نحطه جوه onclick كنص خام (ده كان بيبوظ لو الاسم فيه علامة اقتباس)
        let patientNameById = {{}};

        function loadTableData() {{
            if (!window.pywebview || !window.pywebview.api || !currentRole) return;
            window.pywebview.api.get_patients_list().then(patients => {{
                const tbody = document.getElementById('patientTable');
                tbody.innerHTML = '';
                if (!patients || patients.length === 0) {{
                    tbody.innerHTML = '<tr><td colspan="10" style="text-align:center; padding:20px;">لا توجد بيانات مرضى مسجلة حالياً</td></tr>';
                    return;
                }}

                patients.forEach(rawP => {{
                    patientNameById[rawP.id] = rawP.name || '';
                    const p = escapedPatient(rawP);
                    const tr = document.createElement('tr');
                    tr.id = 'row-' + p.id;
                    tr.onclick = function() {{ selectRow(rawP.id, rawP.name); }};

                    let delBtn = checkPermission('delete') ? `<button class="btn-act btn-delete" onclick="event.stopPropagation(); deletePatient(${{p.id}})">🗑️</button>` : '';
                    let editBtn = checkPermission('edit') ? `<button class="btn-act btn-edit" onclick="event.stopPropagation(); editPatient(${{p.id}})">✏️ تعديل</button>` : '';

                    tr.innerHTML = `
                        <td style="text-align:center;" onclick="event.stopPropagation();"><input type="checkbox" class="patient-cb" value="${{p.id}}" onchange="updateSelectedBanner()"></td>
                        <td><b>${{p.code || '-'}}</b></td>
                        <td><b>${{p.name || '-'}}</b></td>
                        <td>${{p.age || '-'}}</td>
                        <td>${{p.contact || '-'}}</td>
                        <td><small>${{p.chief_complaint || '-'}}</small></td>
                        <td><span style="color:#d35400; font-weight:bold;">${{p.diagnosis || '-'}}</span></td>
                        <td>${{p.plan || '-'}}</td>
                        <td><span style="background:#e1f5fe; color:#0288d1; padding:3px 6px; border-radius:4px; font-size:11px;">${{p.status || 'متابعة'}}</span></td>
                        <td style="text-align:center; white-space:nowrap;">
                            ${{editBtn}}
                            <button class="btn-act btn-follow" onclick="event.stopPropagation(); openFollowups(${{p.id}})">📅 المتابعات</button>
                            <button class="btn-act btn-folder" onclick="event.stopPropagation(); openFolder(${{p.id}})">📂 المرفقات</button>
                            <button class="btn-act btn-print" onclick="event.stopPropagation(); printSingleReport(${{p.id}})">📋 طباعة</button>
                            ${{delBtn}}
                        </td>
                    `;
                    tbody.appendChild(tr);
                }});
            }});
        }}

        function openFolder(pId) {{
            window.pywebview.api.open_patient_folder(pId).then(res => {{
                if (res.status === 'success') {{
                    alert('تم فتح مجلد مرفقات المريض بنجاح:\\n' + res.path);
                }}
            }});
        }}

        function openCurrentPatientFolder() {{
            const pId = document.getElementById('p_id').value;
            if (pId) {{
                openFolder(pId);
            }} else {{
                alert('قم بحفظ المريض أولاً لإنشاء مجلد خاص باسمه');
            }}
        }}

        function selectRow(pId, pName) {{
            selectedPatientId = pId;
            document.querySelectorAll('#patientTable tr').forEach(r => r.classList.remove('selected-row'));
            const selRow = document.getElementById('row-' + pId);
            if (selRow) selRow.classList.add('selected-row');
        }}

        function generateSelectedPatientReport() {{
            const ids = getCheckedPatientIds();
            if (ids.length === 0) {{
                if (selectedPatientId) {{
                    printMultipleReports([selectedPatientId]);
                }} else {{
                    alert('من فضلك حدد مريضاً من المربعات (Checkboxes) أولاً لإنشاء التقرير له');
                }}
            }} else {{
                printMultipleReports(ids);
            }}
        }}

        function printSingleReport(pId) {{
            printMultipleReports([pId]);
        }}

        function printMultipleReports(patientIds) {{
            currentReportPatientIds = patientIds;
            Promise.all(patientIds.map(id => window.pywebview.api.get_patient_by_id(id))).then(patients => {{
                let fullHtml = '';
                patients.forEach((rawP, index) => {{
                    if (!rawP) return;
                    const p = escapedPatient(rawP);
                    const symMap = (val) => (val == '1' ? '1 (✓)' : '0 (X)');
                    const pageBreak = index < patients.length - 1 ? 'page-break-after: always; margin-bottom: 25px;' : '';
                    
                    fullHtml += `
                        <div class="excel-sheet-container" style="border:2px solid #000; padding:12px; background:#fff; font-size:12px; direction:rtl; ${{pageBreak}}">
                            <div class="excel-header" style="background:#115173; color:white; font-weight:bold; padding:8px; text-align:center; font-size:14px; border:1px solid #000; margin-bottom:10px;">
                                Pediatric Arrhythmia Outpatient Clinic - Patient Form Sheet (${{index + 1}} من ${{patients.length}})
                            </div>
                            
                            <div class="excel-section" style="border:1px solid #000; padding:8px; margin-bottom:8px; background:#fafafa;">
                                <div style="font-weight:bold; color:#022c43; text-decoration:underline; margin-bottom:6px;">Demographic Information</div>
                                <table style="width:100%; border-collapse:collapse; font-size:11px;">
                                    <tr>
                                        <td style="padding:3px;"><b>Code:</b> ${{p.code || '-'}}</td>
                                        <td style="padding:3px;"><b>Name:</b> ${{p.name || '-'}}</td>
                                        <td style="padding:3px;"><b>Age:</b> ${{p.age || '-'}}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding:3px;"><b>DOB:</b> ${{p.dob || '-'}}</td>
                                        <td style="padding:3px;"><b>Residence:</b> ${{p.residence || '-'}}</td>
                                        <td style="padding:3px;"><b>Contact:</b> ${{p.contact || '-'}}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding:3px;"><b>Date of Visit:</b> ${{p.date_of_visit || '-'}}</td>
                                        <td style="padding:3px;" colspan="2"><b>Local Folder:</b> ${{p.local_folder || 'لا يوجد مرفقات'}}</td>
                                    </tr>
                                </table>
                            </div>

                            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px; margin-bottom:8px;">
                                <div class="excel-section" style="border:1px solid #000; padding:8px; background:#fafafa;">
                                    <div style="font-weight:bold; color:#022c43; text-decoration:underline; margin-bottom:6px;">History of Present Illness (HPI)</div>
                                    <p style="margin-bottom:4px;"><b>Chief Complaint:</b> ${{p.chief_complaint || '-'}}</p>
                                    <p style="margin-bottom:4px;"><b>Onset:</b> ${{p.onset || '-'}} | <b>Duration:</b> ${{p.duration || '-'}}</p>
                                    <p style="margin-bottom:4px;"><b>Severity:</b> ${{p.severity || '-'}} | <b>Frequency:</b> ${{p.frequency || '-'}}</p>
                                    <p style="margin-bottom:4px;"><b>Progression:</b> ${{p.progression || '-'}}</p>
                                    <p style="margin-bottom:4px;"><b>Alleviating:</b> ${{p.alleviating_factors || '-'}} | <b>Aggravating:</b> ${{p.aggravating_factors || '-'}}</p>
                                </div>

                                <div class="excel-section" style="border:1px solid #000; padding:8px; background:#fafafa;">
                                    <div style="font-weight:bold; color:#022c43; text-decoration:underline; margin-bottom:6px;">Associated Symptoms & Signs</div>
                                    <table style="width:100%; border-collapse:collapse; font-size:11px; text-align:center;" border="1">
                                        <tr><td style="padding:2px;">Syncope</td><td>${{symMap(p.sym_syncope)}}</td><td style="padding:2px;">Palpitations</td><td>${{symMap(p.sym_palpitations)}}</td></tr>
                                        <tr><td style="padding:2px;">Chest Pain</td><td>${{symMap(p.sym_chest_pain)}}</td><td style="padding:2px;">Dyspnea</td><td>${{symMap(p.sym_dyspnea)}}</td></tr>
                                        <tr><td style="padding:2px;">Orthopnea</td><td>${{symMap(p.sym_orthopnea)}}</td><td style="padding:2px;">Edema</td><td>${{symMap(p.sym_edema)}}</td></tr>
                                        <tr><td style="padding:2px;">Low COP</td><td>${{symMap(p.sym_low_cop)}}</td><td style="padding:2px;">Cyanosis</td><td>${{symMap(p.sym_cyanosis)}}</td></tr>
                                    </table>
                                </div>
                            </div>

                            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px; margin-bottom:8px;">
                                <div class="excel-section" style="border:1px solid #000; padding:8px; background:#fafafa;">
                                    <div style="font-weight:bold; color:#022c43; text-decoration:underline; margin-bottom:6px;">Past History & Family History</div>
                                    <p style="margin-bottom:4px;"><b>Past Medical:</b> ${{p.past_medical || 'NAD'}}</p>
                                    <p style="margin-bottom:4px;"><b>Past Surgical:</b> ${{p.past_surgical || '-'}}</p>
                                    <p style="margin-bottom:4px;"><b>Consanguinity:</b> ${{p.consanguinity || '-'}} | <b>SCD:</b> ${{p.scd || '-'}}</p>
                                    <p style="margin-bottom:4px;"><b>Family History:</b> ${{p.family_history || '-'}}</p>
                                </div>

                                <div class="excel-section" style="border:1px solid #000; padding:8px; background:#fafafa;">
                                    <div style="font-weight:bold; color:#022c43; text-decoration:underline; margin-bottom:6px;">Investigations & Laboratory</div>
                                    <p style="margin-bottom:4px;"><b>ECG:</b> ${{p.ecg || '-'}} | <b>Holter:</b> ${{p.holter || '-'}}</p>
                                    <p style="margin-bottom:4px;"><b>Echo:</b> ${{p.echo || '-'}}</p>
                                    <p style="margin-bottom:4px;"><b>HB:</b> ${{p.lab_hb || '-'}} | <b>TLC:</b> ${{p.lab_tlc || '-'}} | <b>PLT:</b> ${{p.lab_plt || '-'}}</p>
                                    <p style="margin-bottom:4px;"><b>Thyroid (T3/T4/TSH):</b> ${{p.lab_t3||'-'}} / ${{p.lab_t4||'-'}} / ${{p.lab_tsh||'-'}}</p>
                                </div>
                            </div>

                            <div class="excel-section" style="border:1px solid #000; padding:8px; background:#fafafa;">
                                <div style="font-weight:bold; color:#022c43; text-decoration:underline; margin-bottom:6px;">Diagnosis & Plan of Management</div>
                                <p style="margin-bottom:4px;"><b>Diagnosis:</b> <b style="color:#d35400;">${{p.diagnosis || '-'}}</b></p>
                                <p style="margin-bottom:4px;"><b>Treatment:</b> ${{p.treatment || '-'}}</p>
                                <p style="margin-bottom:4px;"><b>Plan:</b> ${{p.plan || '-'}} | <b>Status:</b> ${{p.status || '-'}}</p>
                            </div>
                        </div>
                    `;
                }});
                
                document.getElementById('viewBody').innerHTML = fullHtml;
                document.getElementById('viewModal').style.display = 'flex';
            }});
        }}

        function exportCurrentReportExcel() {{
            if (currentReportPatientIds && currentReportPatientIds.length === 1) {{
                window.pywebview.api.export_single_patient_excel(currentReportPatientIds[0]).then(res => {{
                    if (res.status === 'success') {{
                        alert('تم تصدير شيت تقرير المريض لـ Excel بنجاح:\\n' + res.path);
                    }} else {{
                        alert('خطأ أثناء التصدير: ' + res.message);
                    }}
                }});
            }} else if (currentReportPatientIds && currentReportPatientIds.length > 1) {{
                window.pywebview.api.export_excel(currentReportPatientIds).then(res => {{
                    if (res.status === 'success') {{
                        alert('تم تصدير بيانات المرضى المحددين لـ Excel بنجاح:\\n' + res.path);
                    }} else {{
                        alert('خطأ أثناء التصدير: ' + res.message);
                    }}
                }});
            }} else {{
                exportExcel();
            }}
        }}

        function generateResearchReport() {{
            currentReportPatientIds = [];
            const checkedIds = getCheckedPatientIds();
            window.pywebview.api.generate_research_report(checkedIds).then(res => {{
                if (res.status === 'success') {{
                    document.getElementById('viewBody').innerHTML = res.html;
                    document.getElementById('viewModal').style.display = 'flex';
                }} else {{
                    alert('لا توجد بيانات كافية لإصدار التقرير البحثي للمرضى المحددين');
                }}
            }});
        }}

        function editPatient(pId) {{
            if (!checkPermission('edit')) {{ alert('عفواً، لا تملك صلاحية تعديل بيانات المرضى'); return; }}
            window.pywebview.api.get_patient_by_id(pId).then(p => {{
                if (!p) return;
                document.getElementById('p_id').value = p.id;
                const fields = [
                    'code', 'name', 'dob', 'age', 'residence', 'contact', 'date_of_visit', 'local_folder',
                    'chief_complaint', 'onset', 'duration', 'severity', 'frequency', 'progression', 'alleviating_factors', 'aggravating_factors', 'other_systems',
                    'sym_syncope', 'sym_palpitations', 'sym_chest_pain', 'sym_dyspnea', 'sym_orthopnea', 'sym_edema', 'sym_low_cop', 'sym_cyanosis',
                    'past_medical', 'past_surgical', 'hospitalizations', 'dev_delay', 'medications', 'natal_events', 'allergies', 'consanguinity', 'scd', 'family_history',
                    'ecg', 'holter', 'echo', 'inv_other',
                    'lab_hb', 'lab_tlc', 'lab_plt', 'lab_t3', 'lab_t4', 'lab_tsh', 'lab_na', 'lab_k', 'lab_mg',
                    'diagnosis', 'treatment', 'plan', 'status'
                ];
                fields.forEach(f => {{
                    const elem = document.getElementById('p_' + f);
                    if (elem) elem.value = p[f] !== undefined && p[f] !== null ? p[f] : '';
                }});
                document.getElementById('patientModal').style.display = 'flex';
            }});
        }}

        function openNewModal() {{
            if (!checkPermission('add')) {{ alert('عفواً، لا تملك صلاحية إضافة مرضى'); return; }}
            document.getElementById('p_id').value = '';
            const inputs = document.querySelectorAll('#patientModal input[type="text"], #patientModal input[type="date"]');
            inputs.forEach(i => i.value = '');
            const selects = document.querySelectorAll('#patientModal select');
            selects.forEach(s => s.value = '1');
            document.getElementById('p_status').value = 'متابعة';
            window.pywebview.api.suggest_patient_code().then(c => {{
                document.getElementById('p_code').value = c || '';
            }});
            document.getElementById('patientModal').style.display = 'flex';
        }}

        function closeModal() {{ document.getElementById('patientModal').style.display = 'none'; }}

        function savePatient() {{
            const fields = [
                'code', 'name', 'dob', 'age', 'residence', 'contact', 'date_of_visit', 'local_folder',
                'chief_complaint', 'onset', 'duration', 'severity', 'frequency', 'progression', 'alleviating_factors', 'aggravating_factors', 'other_systems',
                'sym_syncope', 'sym_palpitations', 'sym_chest_pain', 'sym_dyspnea', 'sym_orthopnea', 'sym_edema', 'sym_low_cop', 'sym_cyanosis',
                'past_medical', 'past_surgical', 'hospitalizations', 'dev_delay', 'medications', 'natal_events', 'allergies', 'consanguinity', 'scd', 'family_history',
                'ecg', 'holter', 'echo', 'inv_other',
                'lab_hb', 'lab_tlc', 'lab_plt', 'lab_t3', 'lab_t4', 'lab_tsh', 'lab_na', 'lab_k', 'lab_mg',
                'diagnosis', 'treatment', 'plan', 'status'
            ];
            const data = {{ id: document.getElementById('p_id').value }};
            fields.forEach(f => {{
                const elem = document.getElementById('p_' + f);
                data[f] = elem ? elem.value : '';
            }});

            if (!data.id && !String(data.code).trim()) {{
                alert('كود المريض مطلوب. اكتب كوداً أو استخدم الكود المقترح.');
                document.getElementById('p_code').focus();
                return;
            }}

            window.pywebview.api.save_patient(data).then(res => {{
                if (res && res.status === 'error') {{
                    alert(res.message);
                    if (res.suggested_code) {{
                        document.getElementById('p_code').value = res.suggested_code;
                    }}
                    document.getElementById('p_code').focus();
                    return;
                }}
                closeModal();
                loadTableData();
            }});
        }}

        function deletePatient(pId) {{
            if (!checkPermission('delete')) {{ alert('عفواً، صلاحية الحذف مقتصرة على مدير النظام (Admin) فقط'); return; }}
            const name = patientNameById[pId] || '';
            if (confirm('هل أنت تأكد من رغبتك في حذف ملف المريض: ' + name + '؟')) {{
                window.pywebview.api.delete_patient(pId).then(res => {{
                    loadTableData();
                }});
            }}
        }}

        function openFollowups(pId) {{
            document.getElementById('fu_patient_id').value = pId;
            const pName = patientNameById[pId] || '';
            document.getElementById('fuTitle').innerText = 'Follow up visits - ' + pName;
            loadFollowupTable(pId);
            document.getElementById('followupModal').style.display = 'flex';
        }}

        function loadFollowupTable(pId) {{
            window.pywebview.api.get_followups(pId).then(list => {{
                const tbody = document.getElementById('followupTable');
                tbody.innerHTML = '';
                if (!list || list.length === 0) {{
                    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">لا توجد زيارات متابعة مسجلة بعد</td></tr>';
                    return;
                }}
                list.forEach(rawF => {{
                    const f = escapedPatient(rawF);
                    tbody.innerHTML += `<tr>
                        <td><b>${{f.visit_date || '-'}}</b></td>
                        <td>${{f.reason || '-'}}</td>
                        <td>${{f.plan_change || '-'}}</td>
                        <td>${{f.weight_bsa || '-'}}</td>
                    </tr>`;
                }});
            }});
        }}

        function saveFollowup() {{
            const pId = document.getElementById('fu_patient_id').value;
            const data = {{
                patient_id: pId,
                visit_date: document.getElementById('fu_date').value,
                weight_bsa: document.getElementById('fu_weight').value,
                reason: document.getElementById('fu_reason').value,
                plan_change: document.getElementById('fu_plan_change').value
            }};
            window.pywebview.api.add_followup(data).then(res => {{
                loadFollowupTable(pId);
                document.getElementById('fu_reason').value = '';
                document.getElementById('fu_plan_change').value = '';
            }});
        }}

        function toggleServerInputs() {{
            const isNet = document.getElementById('mode_network').checked;
            document.getElementById('networkPathBox').style.display = isNet ? 'flex' : 'none';
        }}

        function openSettingsModal() {{
            const canServerSettings = checkPermission('settings');
            const canManageUsers = checkPermission('manage_users');
            if (!canServerSettings && !canManageUsers) {{
                alert('عفواً، لا تملك صلاحية فتح الإعدادات');
                return;
            }}

            document.getElementById('serverSettingsSection').style.display = canServerSettings ? '' : 'none';
            document.getElementById('backupSettingsSection').style.display = canServerSettings ? '' : 'none';
            document.getElementById('usersSection').style.display = canManageUsers ? '' : 'none';
            document.getElementById('rolePermSection').style.display = (currentRole === 'Admin') ? '' : 'none';

            populateRoleOptions();
            if (canManageUsers) loadUsersTable();
            if (currentRole === 'Admin') loadRolePermissionsTable();

            if (canServerSettings) {{
                window.pywebview.api.get_config().then(cfg => {{
                    if (cfg.db_mode === 'network') {{
                        document.getElementById('mode_network').checked = true;
                    }} else {{
                        document.getElementById('mode_local').checked = true;
                    }}
                    document.getElementById('cfg_network_path').value = cfg.network_db_path || '';
                    document.getElementById('cfg_backup_path').value = cfg.backup_path || '';
                    toggleServerInputs();
                }});
            }}

            document.getElementById('settingsModal').style.display = 'flex';
        }}

        function populateRoleOptions() {{
            const sel = document.getElementById('new_role');
            const roles = (currentRole === 'Admin') ? ['Admin', 'Doctor', 'Staff'] : ['Staff'];
            sel.innerHTML = roles.map(r => `<option value="${{r}}">${{r}}</option>`).join('');
        }}

        const ROLE_PERM_COLUMNS = [
            ['add', 'إضافة مريض'],
            ['edit', 'تعديل مريض'],
            ['delete', 'حذف مريض'],
            ['followup', 'متابعات'],
            ['export', 'تصدير بيانات'],
            ['settings', 'إعدادات السيرفر'],
            ['manage_users', 'إدارة المستخدمين'],
        ];
        const ROLE_PERM_FIELD = {{
            add: 'add_patient', edit: 'edit_patient', delete: 'delete_patient',
            followup: 'add_followup', export: 'export_data',
            settings: 'manage_settings', manage_users: 'manage_users',
        }};

        function loadRolePermissionsTable() {{
            window.pywebview.api.get_role_permissions().then(res => {{
                const tbody = document.getElementById('rolePermTableBody');
                tbody.innerHTML = '';
                if (res.status !== 'success') return;
                res.roles.forEach(roleRow => {{
                    const tr = document.createElement('tr');
                    let cellsHtml = `<td style="font-weight:bold;">${{roleRow.role}}</td>`;
                    ROLE_PERM_COLUMNS.forEach(([action]) => {{
                        const field = ROLE_PERM_FIELD[action];
                        const checked = roleRow[field] ? 'checked' : '';
                        cellsHtml += `<td style="text-align:center;"><input type="checkbox" data-field="${{field}}" ${{checked}}></td>`;
                    }});
                    cellsHtml += `<td style="text-align:center;"><button class="btn-act btn-edit" onclick="saveRolePermissions('${{roleRow.role}}', this)">💾</button></td>`;
                    tr.innerHTML = cellsHtml;
                    tbody.appendChild(tr);
                }});
            }});
        }}

        function saveRolePermissions(role, btnEl) {{
            const tr = btnEl.closest('tr');
            const perms = {{}};
            tr.querySelectorAll('input[type=checkbox]').forEach(cb => {{
                perms[cb.dataset.field] = cb.checked;
            }});
            window.pywebview.api.update_role_permissions(role, perms).then(res => {{
                if (res.status === 'success') {{
                    alert(`تم تحديث صلاحيات ${{role}} بنجاح`);
                }} else {{
                    alert(res.message);
                }}
            }});
        }}

        function saveServerSettings() {{
            const mode = document.getElementById('mode_network').checked ? 'network' : 'local';
            const netPath = document.getElementById('cfg_network_path').value;
            const backupPath = document.getElementById('cfg_backup_path').value;

            window.pywebview.api.save_server_config(mode, netPath, backupPath).then(res => {{
                alert(res.message);
            }});
        }}

        function executeBackupNow() {{
            window.pywebview.api.execute_backup_now().then(res => {{
                if (res.status === 'success') {{
                    alert('تم إنشاء نسخة احتياطية فورية بنجاح في المجلد:\\n' + res.path);
                }} else {{
                    alert('خطأ أثناء النسخ الاحتياطي: ' + res.message);
                }}
            }});
        }}

        let editUserId = null;

        let userInfoById = {{}};

        function loadUsersTable() {{
            window.pywebview.api.get_users().then(users => {{
                const tbody = document.getElementById('usersTable');
                tbody.innerHTML = '';
                users.forEach(rawU => {{
                    userInfoById[rawU.id] = {{ username: rawU.username, role: rawU.role }};
                    const u = escapedPatient(rawU);
                    tbody.innerHTML += `<tr>
                        <td>${{u.id}}</td>
                        <td><b>${{u.username}}</b></td>
                        <td><span class="user-badge">${{u.role}}</span></td>
                        <td style="text-align:center; white-space:nowrap;">
                            <button class="btn-act btn-edit" onclick="openEditUser(${{u.id}})">تعديل</button>
                            <button class="btn-act btn-delete" onclick="deleteUser(${{u.id}})">حذف</button>
                        </td>
                    </tr>`;
                }});
            }});
        }}

        function openEditUser(uId) {{
            const info = userInfoById[uId] || {{ username: '', role: 'Staff' }};
            const username = info.username, role = info.role;
            editUserId = uId;
            document.getElementById('editUserLabel').innerText = username;
            const roles = (currentRole === 'Admin') ? ['Admin', 'Doctor', 'Staff'] : ['Staff'];
            const sel = document.getElementById('editUserRole');
            sel.innerHTML = roles.map(r => `<option value="${{r}}" ${{r === role ? 'selected' : ''}}>${{r}}</option>`).join('');
            document.getElementById('editUserPassword').value = '';
            document.getElementById('editUserModal').style.display = 'flex';
        }}

        function submitEditUser() {{
            const newRole = document.getElementById('editUserRole').value;
            const newPassword = document.getElementById('editUserPassword').value;
            window.pywebview.api.update_user(editUserId, newRole, newPassword || null).then(res => {{
                if (res.status === 'success') {{
                    document.getElementById('editUserModal').style.display = 'none';
                    loadUsersTable();
                }} else {{
                    alert(res.message);
                }}
            }});
        }}

        function saveUser() {{
            const u = document.getElementById('new_username').value;
            const p = document.getElementById('new_password').value;
            const r = document.getElementById('new_role').value;
            if (!u || !p) {{ alert('من فضلك ادخل اسم المستخدم وكلمة السر'); return; }}
            window.pywebview.api.add_user(u, p, r).then(res => {{
                if (res.status === 'success') {{
                    document.getElementById('new_username').value = '';
                    document.getElementById('new_password').value = '';
                    loadUsersTable();
                }} else {{
                    alert(res.message);
                }}
            }});
        }}

        function deleteUser(uId) {{
            if (confirm('هل أنت تأكد من حذف هذا المستخدم؟')) {{
                window.pywebview.api.delete_user(uId).then(res => {{
                    if (res.status === 'error') {{
                        alert(res.message);
                    }} else {{
                        loadUsersTable();
                    }}
                }});
            }}
        }}

        function exportExcel() {{
            if (!checkPermission('export')) {{ alert('عفواً، لا تملك صلاحية تصدير البيانات'); return; }}
            const checkedIds = getCheckedPatientIds();
            window.pywebview.api.export_excel(checkedIds).then(res => {{
                if (res.status === 'success') {{
                    alert('تم تصدير البيانات وفتح الملف تلقائياً عبر Excel:\\n' + res.path);
                }} else {{
                    alert('خطأ أثناء التصدير: ' + res.message);
                }}
            }}).catch(err => {{
                alert('حدث خطأ في عملية التصدير: ' + err);
            }});
        }}

        function filterPatients(val) {{
            const term = val.toLowerCase().trim();
            const rows = document.querySelectorAll('#patientTable tr');
            rows.forEach(tr => {{
                const text = tr.innerText.toLowerCase();
                tr.style.display = text.includes(term) ? '' : 'none';
            }});
        }}

        function setLang(lang) {{
            const root = document.getElementById('htmlRoot');
            if (lang === 'en') {{
                root.dir = 'ltr';
                document.getElementById('lblWelcome').innerText = 'Welcome Doctor | 3R Software Solutions';
                document.getElementById('lblReportsSection').innerText = '📌 Reports & Tools:';
                document.getElementById('btnReportSingle').innerText = '📄 Selected Patient Report Generator';
                document.getElementById('btnReportResearch').innerText = '📊 Arrhythmia Research Paper Report';
                document.getElementById('lblFilesSection').innerText = '📁 File Management:';
                document.getElementById('btnAddPatient').innerText = '+ Add New Patient (Sheet View)';
                document.getElementById('btnExportCSV').innerText = '💾 Export Database (Excel/CSV)';
                document.getElementById('lblSettingsSection').innerText = '⚙️ System & Settings:';
                document.getElementById('btnSettings').innerText = '⚙️ Server & Backup Settings';
                document.getElementById('searchBox').placeholder = 'Search by Name or Code...';
            }} else {{
                root.dir = 'rtl';
                document.getElementById('lblWelcome').innerText = 'مرحباً بك دكتور | 3R Software Solutions';
                document.getElementById('lblReportsSection').innerText = '📌 أدوات التقارير والبحث:';
                document.getElementById('btnReportSingle').innerText = '📄 مولد تقرير المريض (المحدد بالشيت)';
                document.getElementById('btnReportResearch').innerText = '📊 تقرير الأريثما (للمرضى المحددين)';
                document.getElementById('lblFilesSection').innerText = '📁 إدارة الملفات:';
                document.getElementById('btnAddPatient').innerText = '+ إضافة مريض جديد (واجهة الشيت)';
                document.getElementById('btnExportCSV').innerText = '💾 تصدير قاعدة البيانات (Excel/CSV)';
                document.getElementById('lblSettingsSection').innerText = '⚙️ النظام والإعدادات:';
                document.getElementById('btnSettings').innerText = '⚙️ إعدادات السيرفر والنسخ الاحتياطي';
                document.getElementById('searchBox').placeholder = 'بحث باسم الطفل أو الكود...';
            }}
        }}

        // -----------------------------------------------------------
        // أول تشغيل: إنشاء حساب Admin
        // -----------------------------------------------------------
        function submitFirstAdmin() {{
            const u = document.getElementById('setupUsername').value.trim();
            const p1 = document.getElementById('setupPassword').value;
            const p2 = document.getElementById('setupPasswordConfirm').value;
            const err = document.getElementById('setupErrorMsg');
            err.style.display = 'none';

            if (p1 !== p2) {{
                err.innerText = 'كلمة السر وتأكيدها غير متطابقين';
                err.style.display = 'block';
                return;
            }}
            window.pywebview.api.create_first_admin(u, p1).then(res => {{
                if (res.status === 'success') {{
                    document.getElementById('setupCard').style.display = 'none';
                    document.getElementById('loginCard').style.display = 'block';
                    document.getElementById('loginUsername').value = u;
                    document.getElementById('loginPassword').focus();
                }} else {{
                    err.innerText = res.message;
                    err.style.display = 'block';
                }}
            }});
        }}

        // -----------------------------------------------------------
        // وضع الصيانة (استرجاع كلمة السر بدون إنترنت)
        // -----------------------------------------------------------
        function openRecoveryModal() {{
            document.getElementById('loginCard').style.display = 'none';
            document.getElementById('recoveryCard').style.display = 'block';
            document.getElementById('recoveryStep2').style.display = 'none';
            document.getElementById('recoveryErrorMsg').style.display = 'none';
            window.pywebview.api.list_admin_usernames().then(names => {{
                const sel = document.getElementById('recoveryUsername');
                sel.innerHTML = '';
                names.forEach(n => {{
                    const opt = document.createElement('option');
                    opt.value = n; opt.textContent = n;
                    sel.appendChild(opt);
                }});
            }});
        }}

        function closeRecoveryModal() {{
            document.getElementById('recoveryCard').style.display = 'none';
            document.getElementById('loginCard').style.display = 'block';
        }}

        function requestRecoveryChallenge() {{
            const u = document.getElementById('recoveryUsername').value;
            window.pywebview.api.get_recovery_challenge(u).then(res => {{
                const err = document.getElementById('recoveryErrorMsg');
                if (res.status !== 'success') {{
                    err.innerText = res.message;
                    err.style.display = 'block';
                    return;
                }}
                document.getElementById('recoveryChallengeBox').value = res.challenge;
                document.getElementById('recoveryStep2').style.display = 'block';
                err.style.display = 'none';
            }});
        }}

        function submitRecoveryCode() {{
            const u = document.getElementById('recoveryUsername').value;
            const sig = document.getElementById('recoverySignature').value.trim();
            const newPass = document.getElementById('recoveryNewPassword').value;
            const err = document.getElementById('recoveryErrorMsg');
            window.pywebview.api.redeem_recovery_code(u, sig, newPass).then(res => {{
                if (res.status === 'success') {{
                    alert('تم تغيير كلمة السر بنجاح، من فضلك سجّل الدخول بكلمة السر الجديدة');
                    closeRecoveryModal();
                    document.getElementById('loginUsername').value = u;
                    document.getElementById('loginPassword').value = '';
                }} else {{
                    err.innerText = res.message;
                    err.style.display = 'block';
                }}
            }});
        }}

        window.addEventListener('pywebviewready', () => {{
            window.pywebview.api.has_any_user().then(exists => {{
                if (!exists) {{
                    document.getElementById('loginCard').style.display = 'none';
                    document.getElementById('setupCard').style.display = 'block';
                    document.getElementById('setupUsername').focus();
                }} else {{
                    document.getElementById('loginUsername').focus();
                }}
            }});
        }});
    </script>
</body>
</html>
"""

if __name__ == '__main__':
  if not init_db():
    sys.exit(1)
  logger.info(
      'App starting | python=%s | os=%s | frozen=%s | db=%s',
      platform.python_version(),
      platform.platform(),
      getattr(sys, 'frozen', False),
      get_db_path(),
  )
  api = ClinicAPI()
  html_code = build_html_page()

  window = webview.create_window(
      '3R Software Solutions - نظام عيادة أطفال اضطرابات ضربات القلب',
      html=html_code,
      js_api=api,
      width=1340,
      height=890,
  )
  webview.start(debug=False)
  logger.info('App closed')