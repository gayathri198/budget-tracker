"""
KEC Budget Tracker — Complete Backend v2
Flask + PostgreSQL
Features: Auth, Budget, Expenses, Proposals, 24hr Alerts, Monthly Reports, CSV Downloads
"""
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
import psycopg2, psycopg2.extras, jwt, bcrypt, os, uuid, csv, io
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename
import threading, time

app = Flask(__name__)
CORS(app, origins=["http://localhost:5174","http://localhost:5173","http://localhost:3000","http://localhost:5176","http://localhost:5177"], supports_credentials=True)
app.config['SECRET_KEY']    = os.environ.get('SECRET_KEY',   'kec-budget-secret-2026')
app.config['ADMIN_SECRET']  = os.environ.get('ADMIN_SECRET', 'kec-admin-2026')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
ALLOWED = {'png','jpg','jpeg','gif','pdf'}

def get_db():
    return psycopg2.connect(
        dbname=os.environ.get('DB_NAME','kec_budget_db'),
        user=os.environ.get('DB_USER','postgres'),
        password=os.environ.get('DB_PASSWORD','postgres123'),
        host=os.environ.get('DB_HOST','localhost'),
        port=os.environ.get('DB_PORT','5432'))

def serialize(row):
    return {k:(v.isoformat() if hasattr(v,'isoformat') else v) for k,v in (row or {}).items()}

def allowed_file(fn): return '.' in fn and fn.rsplit('.',1)[1].lower() in ALLOWED

def save_file(f, pfx=''):
    if f and f.filename and allowed_file(f.filename):
        fname = secure_filename(f"{pfx}{uuid.uuid4().hex}_{f.filename}")
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
        return f"/uploads/{fname}"
    return None

# ══════════════════════════════════════════════════════════════════
# DB INIT
# ══════════════════════════════════════════════════════════════════
def init_db():
    conn = get_db(); cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'user',
        full_name VARCHAR(255),
        department VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS budgets(
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        academic_year VARCHAR(20) NOT NULL,
        recurring DECIMAL(14,2) DEFAULT 0, programmes DECIMAL(14,2) DEFAULT 0,
        equipment DECIMAL(14,2) DEFAULT 0, computers  DECIMAL(14,2) DEFAULT 0,
        software  DECIMAL(14,2) DEFAULT 0, furniture  DECIMAL(14,2) DEFAULT 0,
        lab_class DECIMAL(14,2) DEFAULT 0, imprest    DECIMAL(14,2) DEFAULT 0,
        created_by UUID REFERENCES users(id),
        created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS expenses(
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id),
        category VARCHAR(50) NOT NULL,
        sub_category VARCHAR(100),
        description TEXT NOT NULL,
        amount DECIMAL(14,2) NOT NULL,
        vendor VARCHAR(255),
        quantity VARCHAR(100),
        notes TEXT,
        bill_url TEXT,
        expense_date DATE DEFAULT CURRENT_DATE,
        status VARCHAR(20) DEFAULT 'pending',
        reviewed_by UUID REFERENCES users(id),
        reviewed_at TIMESTAMP,
        rejection_reason TEXT,
        proposal_id UUID,
        created_at TIMESTAMP DEFAULT NOW()
    );
    -- Add proposal_id column if it doesn't exist (migration)
    DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='expenses' AND column_name='proposal_id') THEN
            ALTER TABLE expenses ADD COLUMN proposal_id UUID;
        END IF;
    END $$;
    CREATE TABLE IF NOT EXISTS proposals(
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id),
        title VARCHAR(255) NOT NULL,
        description TEXT,
        category VARCHAR(50),
        amount DECIMAL(14,2),
        urgency VARCHAR(20) DEFAULT 'normal',
        status VARCHAR(20) DEFAULT 'pending',
        reviewed_by UUID REFERENCES users(id),
        reviewed_at TIMESTAMP,
        rejection_reason TEXT,
        expense_entry_due TIMESTAMP,
        entry_alert_sent_count INT DEFAULT 0,
        last_alert_sent TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS alerts(
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id),
        proposal_id UUID REFERENCES proposals(id),
        message TEXT,
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
    );
    """)
    conn.commit()
    cur.execute("SELECT id FROM users WHERE role='admin' LIMIT 1")
    if not cur.fetchone():
        pw = bcrypt.hashpw(b'admin123', bcrypt.gensalt()).decode()
        cur.execute("INSERT INTO users(email,password_hash,role,full_name,department) VALUES(%s,%s,'admin','System Admin','Computer Applications')",
                    ('admin@kec.ac.in',pw))
        conn.commit(); print("  Default admin: admin@kec.ac.in / admin123")
    cur.execute("SELECT id FROM budgets WHERE academic_year='2026-27' LIMIT 1")
    if not cur.fetchone():
        cur.execute("INSERT INTO budgets(academic_year,recurring,programmes) VALUES('2026-27',60000,348000)")
        conn.commit()
    cur.close(); conn.close()
    print("✓ DB ready.")

# ══════════════════════════════════════════════════════════════════
# AUTH DECORATORS
# ══════════════════════════════════════════════════════════════════
def token_required(f):
    @wraps(f)
    def d(*a,**kw):
        tok = request.headers.get('Authorization','').replace('Bearer ','').strip()
        if not tok: return jsonify({'error':'Token required'}),401
        try: payload = jwt.decode(tok,app.config['SECRET_KEY'],algorithms=['HS256'])
        except jwt.ExpiredSignatureError: return jsonify({'error':'Token expired'}),401
        except: return jsonify({'error':'Invalid token'}),401
        return f(payload,*a,**kw)
    return d

def admin_required(f):
    @wraps(f)
    def d(cu,*a,**kw):
        if cu['role']!='admin': return jsonify({'error':'Admin required'}),403
        return f(cu,*a,**kw)
    return d

# ══════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    for f in ('email','password','full_name'):
        if not data.get(f): return jsonify({'error':f'"{f}" required'}),400
    role = data.get('role','user')
    if role=='admin' and data.get('admin_secret')!=app.config['ADMIN_SECRET']:
        return jsonify({'error':'Invalid admin secret key'}),403
    if len(data['password'])<6: return jsonify({'error':'Password min 6 chars'}),400
    pw = bcrypt.hashpw(data['password'].encode(),bcrypt.gensalt()).decode()
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("INSERT INTO users(email,password_hash,role,full_name,department) VALUES(%s,%s,%s,%s,%s) RETURNING id,email,role,full_name,department",
                    (data['email'],pw,role,data['full_name'],data.get('department','Computer Applications')))
        user=dict(cur.fetchone()); conn.commit(); cur.close(); conn.close()
        return jsonify({'message':'Account created!','user':user}),201
    except psycopg2.IntegrityError: return jsonify({'error':'Email already registered'}),409
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    if not data.get('email') or not data.get('password'): return jsonify({'error':'Email and password required'}),400
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM users WHERE LOWER(email)=LOWER(%s)",(data['email'],))
        user=cur.fetchone(); cur.close(); conn.close()
        if not user or not bcrypt.checkpw(data['password'].encode(),user['password_hash'].encode()):
            return jsonify({'error':'Invalid email or password'}),401
        if data.get('role') and user['role']!=data['role']:
            return jsonify({'error':f'This is not a {data["role"]} account'}),403
        token = jwt.encode({'user_id':str(user['id']),'email':user['email'],'role':user['role'],'exp':datetime.utcnow()+timedelta(days=7)},
                           app.config['SECRET_KEY'],algorithm='HS256')
        return jsonify({'token':token,'user':{'id':str(user['id']),'email':user['email'],'role':user['role'],'full_name':user['full_name'],'department':user['department']}})
    except Exception as e: return jsonify({'error':str(e)}),500

# ══════════════════════════════════════════════════════════════════
# BUDGET
# ══════════════════════════════════════════════════════════════════
@app.route('/api/budget/current', methods=['GET'])
@token_required
def get_budget(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM budgets ORDER BY created_at DESC LIMIT 1")
        b=cur.fetchone(); cur.close(); conn.close()
        if not b: return jsonify({'budget':None})
        row=dict(b)
        sanctioned={k:float(row[k]) for k in ['recurring','programmes','equipment','computers','software','furniture','lab_class','imprest']}
        return jsonify({'budget':{'id':str(row['id']),'academic_year':row['academic_year'],'sanctioned':sanctioned}})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/budget/set', methods=['POST'])
@token_required
@admin_required
def set_budget(cu):
    data=request.get_json() or {}; s=data.get('sanctioned',{})
    yr=data.get('academic_year','2026-27')
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT id FROM budgets WHERE academic_year=%s",(yr,))
        if cur.fetchone():
            cur.execute("UPDATE budgets SET recurring=%s,programmes=%s,equipment=%s,computers=%s,software=%s,furniture=%s,lab_class=%s,imprest=%s WHERE academic_year=%s",
                        (s.get('recurring',0),s.get('programmes',0),s.get('equipment',0),s.get('computers',0),s.get('software',0),s.get('furniture',0),s.get('lab_class',0),s.get('imprest',0),yr))
        else:
            cur.execute("INSERT INTO budgets(academic_year,recurring,programmes,equipment,computers,software,furniture,lab_class,imprest,created_by) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (yr,s.get('recurring',0),s.get('programmes',0),s.get('equipment',0),s.get('computers',0),s.get('software',0),s.get('furniture',0),s.get('lab_class',0),s.get('imprest',0),cu['user_id']))
        conn.commit(); cur.close(); conn.close()
        return jsonify({'message':'Budget saved!'})
    except Exception as e: return jsonify({'error':str(e)}),500

# ══════════════════════════════════════════════════════════════════
# EXPENSES
# ══════════════════════════════════════════════════════════════════
@app.route('/api/expenses', methods=['POST'])
@token_required
def add_expense(cu):
    data=request.form
    if not data.get('description'): return jsonify({'error':'Description required'}),400
    if not data.get('amount'):       return jsonify({'error':'Amount required'}),400
    if not data.get('category'):     return jsonify({'error':'Category required'}),400
    bill_url=save_file(request.files.get('bill'),'bill_')
    proposal_id=data.get('proposal_id') or None
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""INSERT INTO expenses(user_id,category,sub_category,description,amount,vendor,quantity,notes,bill_url,expense_date,status,proposal_id)
                       VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'pending',%s) RETURNING *""",
                    (cu['user_id'],data.get('category'),data.get('sub_category'),data.get('description'),
                     float(data.get('amount',0)),data.get('vendor'),data.get('quantity'),
                     data.get('notes'),bill_url,data.get('date',str(datetime.now().date())),proposal_id))
        exp=serialize(dict(cur.fetchone())); conn.commit(); cur.close(); conn.close()
        return jsonify({'expense':exp,'message':'Expense submitted!'}),201
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/expenses', methods=['GET'])
@token_required
def list_expenses(cu):
    limit=int(request.args.get("limit",200))
    proposal_id=request.args.get("proposal_id")
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        if proposal_id:
            cur.execute("SELECT * FROM expenses WHERE user_id=%s AND proposal_id=%s ORDER BY created_at DESC LIMIT %s",(cu["user_id"],proposal_id,limit))
        elif cu["role"]=="admin":
            cur.execute("SELECT e.*,u.full_name AS user_name,u.email AS user_email FROM expenses e LEFT JOIN users u ON e.user_id=u.id ORDER BY e.created_at DESC LIMIT %s",(limit,))
        else:
            cur.execute("SELECT * FROM expenses WHERE user_id=%s ORDER BY created_at DESC LIMIT %s",(cu["user_id"],limit))
        exps=[serialize(dict(r)) for r in cur.fetchall()]
        cur.close(); conn.close()
        return jsonify({"expenses":exps})
    except Exception as e: return jsonify({"error":str(e)}),500

# ══════════════════════════════════════════════════════════════════
# DASHBOARD STATS
# ══════════════════════════════════════════════════════════════════
@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
def dashboard_stats(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        uid=cu['user_id']; is_admin=(cu['role']=='admin')
        def q_sum(extra=''):
            if is_admin: return f"SELECT COALESCE(SUM(amount),0) AS s FROM expenses WHERE status!='rejected' {extra}"
            return f"SELECT COALESCE(SUM(amount),0) AS s FROM expenses WHERE user_id='{uid}' AND status!='rejected' {extra}"
        cur.execute(q_sum()); total_spent=float(cur.fetchone()['s'])
        if is_admin: cur.execute("SELECT COUNT(*) AS c FROM expenses")
        else:        cur.execute("SELECT COUNT(*) AS c FROM expenses WHERE user_id=%s",(uid,))
        total_exp=int(cur.fetchone()['c'])
        cats=['recurring','programmes','equipment','computers','software','furniture','lab_class','imprest']
        by_cat={}
        for cat in cats:
            cur.execute(q_sum(f"AND category='{cat}'"))
            by_cat[cat]=float(cur.fetchone()['s'])
        cur.close(); conn.close()
        return jsonify({'total_spent':total_spent,'total_expenses':total_exp,'by_category':by_cat})
    except Exception as e: return jsonify({'error':str(e)}),500

# ══════════════════════════════════════════════════════════════════
# PROPOSALS
# ══════════════════════════════════════════════════════════════════
@app.route('/api/proposals', methods=['POST'])
@token_required
def create_proposal(cu):
    data=request.get_json() or {}
    if not data.get('title'):  return jsonify({'error':'Title required'}),400
    if not data.get('amount'): return jsonify({'error':'Amount required'}),400
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""INSERT INTO proposals(user_id,title,description,category,amount,urgency,status)
                       VALUES(%s,%s,%s,%s,%s,%s,'pending') RETURNING *""",
                    (cu['user_id'],data['title'],data.get('description'),data.get('category','recurring'),
                     float(data['amount']),data.get('urgency','normal')))
        prop=serialize(dict(cur.fetchone())); conn.commit(); cur.close(); conn.close()
        return jsonify({'proposal':prop,'message':'Proposal raised!'}),201
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/proposals', methods=['GET'])
@token_required
def my_proposals(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM proposals WHERE user_id=%s ORDER BY created_at DESC",(cu['user_id'],))
        props=[serialize(dict(r)) for r in cur.fetchall()]
        cur.close(); conn.close()
        return jsonify({'proposals':props})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/proposals/all', methods=['GET'])
@token_required
@admin_required
def all_proposals(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT p.*,u.full_name AS user_name,u.email AS user_email FROM proposals p LEFT JOIN users u ON p.user_id=u.id ORDER BY p.created_at DESC")
        props=[serialize(dict(r)) for r in cur.fetchall()]
        cur.close(); conn.close()
        return jsonify({'proposals':props})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/proposals/<pid>/approve', methods=['POST'])
@token_required
@admin_required
def approve_proposal(cu, pid):
    try:
        conn=get_db(); cur=conn.cursor()
        due = datetime.utcnow() + timedelta(hours=24)
        cur.execute("UPDATE proposals SET status='approved',reviewed_by=%s,reviewed_at=NOW(),expense_entry_due=%s WHERE id=%s",
                    (cu['user_id'],due,pid))
        # create alert for user
        cur.execute("SELECT user_id,title FROM proposals WHERE id=%s",(pid,))
        row=cur.fetchone()
        if row:
            msg=f"Your proposal '{row[1]}' was approved! Please add expense entries within 24 hours."
            cur.execute("INSERT INTO alerts(user_id,proposal_id,message) VALUES(%s,%s,%s)",(row[0],pid,msg))
        conn.commit(); cur.close(); conn.close()
        return jsonify({'message':'Approved'})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/proposals/<pid>/reject', methods=['POST'])
@token_required
@admin_required
def reject_proposal(cu, pid):
    data=request.get_json() or {}
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("UPDATE proposals SET status='rejected',reviewed_by=%s,reviewed_at=NOW(),rejection_reason=%s WHERE id=%s",
                    (cu['user_id'],data.get('reason',''),pid))
        conn.commit(); cur.close(); conn.close()
        return jsonify({'message':'Rejected'})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/proposals/alerts', methods=['GET'])
@token_required
def get_alerts(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM alerts WHERE user_id=%s AND is_read=FALSE ORDER BY created_at DESC LIMIT 5",(cu['user_id'],))
        alerts=[serialize(dict(r)) for r in cur.fetchall()]
        cur.close(); conn.close()
        return jsonify({'alerts':alerts})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/proposals/alerts/<aid>/read', methods=['POST'])
@token_required
def mark_alert_read(cu, aid):
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("UPDATE alerts SET is_read=TRUE WHERE id=%s AND user_id=%s",(aid,cu['user_id']))
        conn.commit(); cur.close(); conn.close()
        return jsonify({'message':'Marked read'})
    except: return jsonify({'error':'Failed'}),500


@app.route('/api/proposals/<pid>/has_entry', methods=['GET'])
@token_required
def proposal_has_entry(cu, pid):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT COUNT(*) as cnt FROM expenses WHERE user_id=%s AND proposal_id=%s",(cu['user_id'],pid))
        row=cur.fetchone()
        cur.close(); conn.close()
        return jsonify({'has_entry': (row['cnt'] or 0) > 0})
    except Exception as e: return jsonify({'error':str(e)}),500

# ══════════════════════════════════════════════════════════════════
# ADMIN
# ══════════════════════════════════════════════════════════════════
@app.route('/api/admin/expenses', methods=['GET'])
@token_required
@admin_required
def admin_expenses(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT e.*,u.full_name AS user_name,u.email AS user_email,u.department FROM expenses e LEFT JOIN users u ON e.user_id=u.id ORDER BY e.created_at DESC")
        exps=[serialize(dict(r)) for r in cur.fetchall()]
        cur.close(); conn.close()
        return jsonify({'expenses':exps})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/expenses/<eid>/approve', methods=['POST'])
@token_required
@admin_required
def admin_approve_exp(cu, eid):
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("UPDATE expenses SET status='approved',reviewed_by=%s,reviewed_at=NOW() WHERE id=%s",(cu['user_id'],eid))
        conn.commit(); cur.close(); conn.close(); return jsonify({'message':'Approved'})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/expenses/<eid>/reject', methods=['POST'])
@token_required
@admin_required
def admin_reject_exp(cu, eid):
    data=request.get_json() or {}
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("UPDATE expenses SET status='rejected',reviewed_by=%s,reviewed_at=NOW(),rejection_reason=%s WHERE id=%s",(cu['user_id'],data.get('reason',''),eid))
        conn.commit(); cur.close(); conn.close(); return jsonify({'message':'Rejected'})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/users', methods=['GET'])
@token_required
@admin_required
def admin_users(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT id,email,role,full_name,department,created_at FROM users ORDER BY created_at DESC")
        users=[serialize(dict(u)) for u in cur.fetchall()]
        cur.close(); conn.close(); return jsonify({'users':users})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/monthly', methods=['GET'])
@token_required
@admin_required
def admin_monthly(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT TO_CHAR(expense_date,'Mon') AS month,
                   EXTRACT(MONTH FROM expense_date) AS mnum,
                   COALESCE(SUM(amount),0) AS amount
            FROM expenses WHERE status!='rejected'
            GROUP BY month,mnum ORDER BY mnum
        """)
        monthly=[serialize(dict(r)) for r in cur.fetchall()]
        cur.close(); conn.close(); return jsonify({'monthly':monthly})
    except Exception as e: return jsonify({'error':str(e)}),500

# ══════════════════════════════════════════════════════════════════
# REPORTS (CSV Download)
# ══════════════════════════════════════════════════════════════════
@app.route('/api/admin/report/monthly', methods=['GET'])
@token_required
@admin_required
def report_monthly(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        now=datetime.now()
        cur.execute("""SELECT e.*,u.full_name,u.department FROM expenses e
                       LEFT JOIN users u ON e.user_id=u.id
                       WHERE EXTRACT(MONTH FROM e.expense_date)=%s AND EXTRACT(YEAR FROM e.expense_date)=%s
                       AND e.status!='rejected' ORDER BY e.expense_date""",(now.month,now.year))
        rows=cur.fetchall()
        cur.execute("SELECT * FROM budgets ORDER BY created_at DESC LIMIT 1")
        budget=cur.fetchone()
        cur.close(); conn.close()

        out=io.StringIO()
        w=csv.writer(out)
        w.writerow([f'KEC Budget Tracker - Monthly Report ({now.strftime("%B %Y")})'])
        w.writerow([])
        w.writerow(['Date','User','Department','Category','Sub Category','Description','Vendor','Amount (Rs.)','Bill','Status'])
        total=0
        for r in rows:
            w.writerow([r['expense_date'],r['full_name'],r['department'],r['category'],r['sub_category']or'',r['description'],r['vendor']or'',r['amount'],r['bill_url']or'N/A',r['status']])
            total+=float(r['amount'])
        w.writerow([]); w.writerow(['','','','','','','TOTAL',total,'',''])
        if budget:
            w.writerow([]); w.writerow(['Budget Summary'])
            cats=['recurring','programmes','equipment','computers','software','furniture','lab_class','imprest']
            for c in cats:
                w.writerow([c.replace('_',' ').title(), f"Sanctioned: {budget[c]}", f"Total spent this month: (see above)"])
        buf=io.BytesIO(out.getvalue().encode('utf-8-sig'))
        buf.seek(0)
        return send_file(buf,mimetype='text/csv',as_attachment=True,download_name=f'kec_monthly_{now.strftime("%Y_%m")}.csv')
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/report/yearly', methods=['GET'])
@token_required
@admin_required
def report_yearly(cu):
    try:
        conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        yr=datetime.now().year
        cur.execute("""SELECT e.*,u.full_name,u.department FROM expenses e
                       LEFT JOIN users u ON e.user_id=u.id
                       WHERE EXTRACT(YEAR FROM e.expense_date)=%s AND e.status!='rejected'
                       ORDER BY e.expense_date""",(yr,))
        rows=cur.fetchall()
        cur.execute("SELECT * FROM budgets ORDER BY created_at DESC LIMIT 1")
        budget=cur.fetchone()
        cur.close(); conn.close()

        out=io.StringIO()
        w=csv.writer(out)
        w.writerow([f'KEC Budget Tracker - Annual Report {yr}'])
        w.writerow(['Kongu Engineering College, Perundurai - Dept. of Computer Applications'])
        w.writerow([])
        w.writerow(['Date','User','Department','Category','Description','Vendor','Amount (Rs.)','Bill','Status'])
        total=0
        month_totals: dict = {}
        for r in rows:
            mn=str(r['expense_date'])[:7] if r['expense_date'] else 'Unknown'
            month_totals[mn]=month_totals.get(mn,0)+float(r['amount'])
            w.writerow([r['expense_date'],r['full_name'],r['department'],r['category'],r['description'],r['vendor']or'',r['amount'],r['bill_url']or'N/A',r['status']])
            total+=float(r['amount'])

        w.writerow([]); w.writerow(['TOTAL ANNUAL EXPENDITURE',total])
        w.writerow([]); w.writerow(['Month-wise Summary'])
        w.writerow(['Month','Amount (Rs.)'])
        for m,amt in sorted(month_totals.items()): w.writerow([m,amt])

        if budget:
            cats=['recurring','programmes','equipment','computers','software','furniture','lab_class','imprest']
            w.writerow([]); w.writerow(['Budget vs Actual Summary'])
            w.writerow(['Category','Sanctioned (Rs.)'])
            total_s=0
            for c in cats:
                w.writerow([c.replace('_',' ').title(),budget[c]]); total_s+=float(budget[c])
            w.writerow(['TOTAL SANCTIONED',total_s])
            w.writerow(['TOTAL SPENT',total])
            w.writerow(['BALANCE',total_s-total])

        buf=io.BytesIO(out.getvalue().encode('utf-8-sig'))
        buf.seek(0)
        return send_file(buf,mimetype='text/csv',as_attachment=True,download_name=f'kec_annual_{yr}.csv')
    except Exception as e: return jsonify({'error':str(e)}),500

# ══════════════════════════════════════════════════════════════════
# ALERT SCHEDULER (every 3 hrs)
# ══════════════════════════════════════════════════════════════════
def check_proposal_alerts():
    while True:
        try:
            conn=get_db(); cur=conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            # Find approved proposals where deadline passed and no expense added, alert every 3 hrs
            cur.execute("""
                SELECT p.*,u.full_name FROM proposals p
                JOIN users u ON p.user_id=u.id
                WHERE p.status='approved'
                AND p.expense_entry_due IS NOT NULL
                AND (p.last_alert_sent IS NULL OR p.last_alert_sent < NOW() - INTERVAL '3 hours')
            """)
            overdue = cur.fetchall()
            for p in overdue:
                # Check if expense was made after approval
                cur.execute("SELECT COUNT(*) AS c FROM expenses WHERE user_id=%s AND created_at > %s",(p['user_id'],p['reviewed_at']))
                cnt=cur.fetchone()['c']
                if cnt==0:
                    msg=f"⚠️ Reminder: Your approved proposal '{p['title']}' still needs expense entries. Please add expense details."
                    cur.execute("INSERT INTO alerts(user_id,proposal_id,message) VALUES(%s,%s,%s)",(p['user_id'],p['id'],msg))
                    cur.execute("UPDATE proposals SET entry_alert_sent_count=entry_alert_sent_count+1, last_alert_sent=NOW() WHERE id=%s",(p['id'],))
                    print(f"  Alert sent to {p['full_name']} for proposal: {p['title']}")
            conn.commit(); cur.close(); conn.close()
        except Exception as e:
            print(f"Alert scheduler error: {e}")
        time.sleep(3600*3)  # every 3 hours

# ══════════════════════════════════════════════════════════════════
# STATIC + HEALTH
# ══════════════════════════════════════════════════════════════════
@app.route('/uploads/<path:fn>')
def serve_upload(fn): return send_from_directory(app.config['UPLOAD_FOLDER'],fn)

@app.route('/api/health')
def health():
    try: conn=get_db(); conn.close(); db=True
    except: db=False
    return jsonify({'status':'ok' if db else 'db_error','db':'connected' if db else 'disconnected'})

if __name__=='__main__':
    print("="*55)
    print("  KEC Budget Tracker Backend v2")
    print("  Admin: admin@kec.ac.in / admin123")
    print("="*55)
    try: init_db()
    except Exception as e: print(f"DB warning: {e}")
    # Start alert scheduler in background
    t=threading.Thread(target=check_proposal_alerts,daemon=True)
    t.start(); print("✓ Alert scheduler running.")
    app.run(debug=True,port=5001,host='0.0.0.0')
