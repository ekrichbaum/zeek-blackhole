# -*- coding: utf-8 -*-

import os
import subprocess
import geoip2.database
from IPy import IP
from sqlite3 import dbapi2 as sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash

app = Flask(__name__)

app.config.update(dict(
    DATABASE='/var/www/bro-unblocker/blocked_ips.db',
    DEBUG=True,
    SECRET_KEY='development key'
))

white=['US','MX','CA']
embargo=['CN','HK','CU','IR','RU','SD','SS','SY','TW']

def connect_db():
    """Connects to database."""
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db

def isValidIP(ip):
    try:
        IP(ip)
    except ValueError:
        return False
    else:
        return True

def getCountry(ip):
    try:
        flash("hi")
        reader = geoip2.database.Reader('/var/www/bro-unblocker/geoip.mmdb')
        flash("there")
        response = reader.country(ip)
        cc = response.country.iso_code
    except:
        flash('Error checking geoblock! ',category='error')
    finally:
        return cc

def checkGeo(cc):
    if cc not in white:
        return True
    return False

def isEmbargoed(cc):
    if cc in embargo:
        return True
    return False

def checkDude(ip):
    """ Return True if the ip is whitelisted or unblocked """
    theDude = dudeutils.theDude(ip)
    res = theDude.abides(theDude.check_ip)
    if res == "ERROR":
        flash("ERROR with DUDE!")
    else:
        for host, results in res.items():
            for out in results['stdout']:
                if 'is in set' in out:
                    return True
    return False

def dudeUnblock(ip):
    theDude = dudeutils.theDude(ip)
    res = theDude.abides(theDude.unblock_ip)
    for host, results in res.items():
        if results['status'].find('failed') >= 0:
            return False
    return True

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()

@app.route('/')
def mainpage():
    return render_template('index.html')

@app.route('/checkip', methods=['POST'])
def checkip():
    ip=request.form['ip']
    if not isValidIP(ip):
        flash('Invalid IP entered!',category='error')
        return redirect(url_for('mainpage'))

    cc = getCountry(ip)

    if isEmbargoed(cc):
        flash('IP is from blacklisted country ' + cc + '; will NOT unblock',category='error')
        return redirect(url_for('mainpage'))

    banned = False
    ban_source = []

    flash("Status for IP " + ip, category='info')

    # BRO Check
    cmd = ['sudo', 'vtysh', '-c', 'show ip route ' + ip]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               stdin=subprocess.PIPE)
        out, err = p.communicate()
    except:
        flash('Error checking IPS-Zeek!', category='error')
        out="unknown"
    # Use key = Null0 for Zebra on bro
    # key = 'Null0'
    # Use key = blackhole for FRR on Zeek
    key = 'blackhole'

    if out == 'unknown':
        flash("IPS (Zeek): Unknown", category='info')
    elif key not in str(out):
        flash("IPS (Zeek): not banned", category='info')
    else:
        banned=True
        flash("IPS (Zeek): banned", category='info')

    if banned:
        return render_template("checkip.html", ip=ip, ban_source=ban_source)
    else:
        return redirect(url_for('mainpage'))

    abort(403)

@app.route('/freeip', methods=['POST'])
def freeip():
    ip=request.form['ip']
    customer=request.form['customer']
    db = get_db()
    db.execute('UPDATE blocked_ips SET whitelistip=1, whitelistcust=? WHERE ip=?',
               [customer, ip])
    db.commit()

    cmd = ['sudo', 'vtysh', '-c', 'config t', '-c', 'no ip route ' + ip + '/32 null0', '-c', 'exit']
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           stdin=subprocess.PIPE)
    out, err = p.communicate()

    flash('Unblock command for ' + ip + ' was submitted to IPS (Zeek)',category='info')

    return redirect(url_for('mainpage'))

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=6543,debug=True)
