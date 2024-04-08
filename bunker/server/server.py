# Copyright Lewis Goldenberg 2024
"""
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

from flask import Flask, redirect, request
from Crypto.Random import get_random_bytes
import jwt
from datetime import *
import base64
import json
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from sqlalchemy import *

engine = create_engine('sqlite:///users.db', echo = True)
meta = MetaData()
users = Table(
    'users', meta,
    Column('username', String, primary_key = True),
    Column('ec_x', BLOB), 
    Column('ec_y', BLOB),
)
print("these are columns in our table %s" %(users.columns.keys()))
meta.create_all(engine)
app = Flask(__name__)
secret_key = get_random_bytes(1024)
@app.route('/')
def hello():
    return redirect("http://127.0.0.1:5000/registration_start")

@app.route("/registration_start", methods=["POST"])
def mainone():
    challenge = get_random_bytes(32)
    encoded_jwt = jwt.encode({
        "chal": base64.b64encode(challenge).decode("utf-8"),
        "exp": datetime.now(tz=timezone.utc) + timedelta(seconds=30)
    }, secret_key, algorithm="HS256")
    return encoded_jwt

@app.route("/registration_finish", methods=["POST"])
def maintwo():
    data = json.loads(request.data)
    decodedr = base64.b64decode(data['r'] + "==")
    decodeds = base64.b64decode(data['s'] + "==")
    decodedjwt = jwt.decode(data['jwt'], secret_key, leeway=10, algorithms=["HS256"])
    decodedchal = base64.b64decode(decodedjwt['chal'])
    rpluss = decodedr+decodeds
    k = ECC.construct(point_x=data['ec_x'],point_y=data['ec_y'],curve="p256")
    verifier = DSS.new(k, "fips-186-3")
    h = SHA256.new(decodedchal)
    verifier.verify(h, rpluss)
    print("signature is valid!")
    #STORE MAGIC
    ins = users.insert().values(username = data["username"], ec_x = data["ec_x"].to_bytes(32, "big"), ec_y = data["ec_y"].to_bytes(32, "big"))
    conn = engine.connect()
    result = conn.execute(ins)
    conn.commit()
    print("properly stored")
    return "fin"
@app.route("/authentication_start", methods=["POST"])
def mainthree():
    print("properly pulled")
    challenge = get_random_bytes(32)
    encoded_jwt = jwt.encode({
    "chal": base64.b64encode(challenge).decode("utf-8"),
    "exp": datetime.now(tz=timezone.utc) + timedelta(seconds=30),
    "username": request.data.decode("utf-8")
    }, secret_key, algorithm="HS256")
    return encoded_jwt
        

@app.route("/authentication_finish", methods=["POST"])
def mainfour():
    data = json.loads(request.data)
    decodedr = base64.b64decode(data['r'] + "==")
    decodeds = base64.b64decode(data['s'] + "==")
    decodedjwt = jwt.decode(data['jwt'], secret_key, leeway=10, algorithms=["HS256"])

    sel = select(users).where(users.c.username == decodedjwt["username"])
    conn = engine.connect()
    result = conn.execute(sel)
    (_, ec_x, ec_y) = result.fetchone()
    ec_x = int.from_bytes(ec_x, "big")
    ec_y = int.from_bytes(ec_y, "big")

    decodedchal = base64.b64decode(decodedjwt['chal'])

    rpluss = decodedr+decodeds
    k = ECC.construct(point_x=ec_x,point_y=ec_y,curve="p256")
    verifier = DSS.new(k, "fips-186-3")
    h = SHA256.new(decodedchal)
    verifier.verify(h, rpluss)
    print("signature is valid!")

    encoded_jwt_login = jwt.encode({
        "username": decodedjwt["username"],
        "exp": datetime.now(tz=timezone.utc) + timedelta(seconds=3000)
    }, secret_key, algorithm="HS256")
    return encoded_jwt_login


if __name__ == "__main__":
    app.run()
