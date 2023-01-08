#!/usr/bin/env python
# -*- coding: utf-8 -*-
import config
from functools import wraps
from flask import Flask, request, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
import xml.etree.ElementTree as etree
import sys
import logging

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://{user}:{password}@{host}/{dbname}'.format(user=config.database['user'], password=config.database['password'], host=config.database['host'], dbname=config.database['dbname'])
db = SQLAlchemy(app)
logging.basicConfig(filename='hazard.log',level=logging.DEBUG, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
console = logging.StreamHandler(sys.stderr)
console.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(message)s')
console.setFormatter(formatter)
logging.getLogger("").addHandler(console)

class Domain(db.Model):
    __tablename__ = 'domains'
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(255), index=True, unique=True)
    master = db.Column(db.String(128))
    last_check = db.Column(db.Integer)
    type = db.Column(db.String(6), nullable = False)
    notified_serial = db.Column(db.Integer)
    records = db.relationship('Record', cascade="all,delete", backref="parent")

    def __init__(self, id=None, name=None, type='NATIVE', master=None, notified_serial=None, last_check = None, records = []):
        self.id = id
        self.name = name
        self.master = master
        self.type = type
        self.notified_serial = notified_serial
        self.last_check = last_check
        self.records = records

    def __repr__(self):
        return '<Domain %r>' % (self.name)

class Record(db.Model):
    __tablename__ = 'records'
    id = db.Column(db.Integer, primary_key = True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domains.id'))
    name = db.Column(db.String(255))
    type = db.Column(db.String(10))
    content = db.Column(db.String(65535))
    ttl = db.Column(db.Integer)
    prio = db.Column(db.Integer)

    def __init__(self, id=None, domain_id = None, name=None, type=None, content=None, ttl=None, prio=None):
        self.id = id
        self.domain_id = domain_id
        self.name = name
        self.type = type
        self.content = content
        self.ttl = ttl
        self.prio = prio

    def __repr__(self):
        return '{0} {1} {2}'.format(self.name, self.type, self.content)



def requires_ssl_check(f):
    """weryfikacja klucza sha1 certyfikatu klienckiego przeslanego w naglowku od nginx"""
    #logging.warning('REQ: {0}'.format(request))
    @wraps(f)
    def decorated(*args, **kwargs):
        access_fingerprint = config.mf['certificate'].lower().replace(':', '')
        client_fingerprint = request.environ.get('X_SSL_FINGERPRINT')
        if access_fingerprint:
            if not access_fingerprint == client_fingerprint:
                logging.warning('Weryfikacja klucza SHA1 się nie powiodła: {0} {1}'.format(client_fingerprint, request.environ))
                return Response('<hazard>\n<status>Not authorized</status>\n<desc>Nie mozna zweryfikowac certyfikatu</desc></hazard>', status=401, mimetype='application/xml')
        return f(*args, **kwargs)
    return decorated


@app.route('/', methods=['POST'])
@requires_ssl_check
def index():
    #logging.warning('TRANSFER DANYCH: {0}'.format(request))
    logging.info('Rozpoczęto transfer danych z ministerstwa finansow')
    """odbiera xml od hazard.mf.gov.pl"""
    try:
        root = etree.fromstring(request.data)
    except Exception as e:
        logging.warning('Bled parsowania xml: {0}'.format(e))
        return Response('<hazard>\n<status>Bad request</status>\n<desc>Bledna tresc xml</desc></hazard>', status=400, mimetype='application/xml')
    for domena in root.findall('.//{http://www.hazard.mf.gov.pl/2017/03/21/}PozycjaRejestru'):
        adres = domena.find('{http://www.hazard.mf.gov.pl/2017/03/21/}AdresDomeny')
        wpis = domena.find('{http://www.hazard.mf.gov.pl/2017/03/21/}DataWpisu')
        wykreslenie = domena.find('{http://www.hazard.mf.gov.pl/2017/03/21/}DataWykreslenia')
        if adres is not None and wpis is not None:
            try:
                if wykreslenie is None:
                    logging.info('Dodaje nowa domene do bazy danych: {0}'.format(adres.text))
                    if None == db.session.query(Domain).filter(Domain.name == adres.text).first():
                        nowa_domena = Domain(name=adres.text)
                        rekord_a = Record(name=adres.text, type='A', content=config.mf['host'])
                        nowa_domena.records.append(rekord_a)
                        rekord_soa = Record(name=adres.text, type='SOA', content=config.mf['host'])
                        nowa_domena.records.append(rekord_soa)
                        rekord_ns1 = Record(name=adres.text, type='NS', content=config.ns1)
                        rekord_ns2 = Record(name=adres.text, type='NS', content=config.ns2)
                        nowa_domena.records.append(rekord_ns1)
                        nowa_domena.records.append(rekord_ns2)
                        db.session.add(nowa_domena)
                else:
                    logging.info('Usuwam domene z bazy danych: {0}'.format(adres.text))
                    do_usuniecia = db.session.query(Domain).filter(Domain.name == adres.text).first()
                    if do_usuniecia is not None:
                        db.session.delete(do_usuniecia)
            except Exception as e:
                logging.error('Blad podczas parsowania domeny {0}: {1}'.format(adres.text, e))
                return Response('<hazard>\n<status>Internal error</status>\n<desc>Przerwano przyjmowanie wiadomosci ze wzgledu na blad wewnetrzny</desc></hazard>', status=500, mimetype='application/xml')
    db.session.commit()
    logging.info('Zakonczono transfer danych z ministerstwa.')
    response = Response('<hazard>\n<status>OK</status>\n</hazard>', mimetype='application/xml')
    response.headers['Rsh-Push'] = 'accepted';
    return response

if __name__ == "__main__":
    app.run(host='0.0.0.0')
