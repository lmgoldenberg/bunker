# Copyright James Connolly 2024
"""
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

import requests
import json
import base64
from websockets.sync.client import connect
import msgpack

username = input("username: ")
r = requests.post("http://127.0.0.1:5000/registration_start")
jwt = r.text
claims = json.loads(base64.b64decode(jwt.split('.')[1] + "===").decode("utf-8"))
challenge = base64.b64decode(claims["chal"])

with connect("ws://127.0.0.1:8000") as ws:
	msg = msgpack.packb({
		"Sign": [
			"example.com",
			list(challenge),
			True
		]
	})
	ws.send(msg)
	resp = msgpack.unpackb(ws.recv())

r = base64.b64encode(bytes(resp["Sign"][0])).decode("utf-8")
s = base64.b64encode(bytes(resp["Sign"][1])).decode("utf-8")
ec_x = int.from_bytes(bytes(resp["Sign"][2][0]), "big")
ec_y = int.from_bytes(bytes(resp["Sign"][2][1]), "big")

r = requests.post("http://127.0.0.1:5000/registration_finish", json={
	"jwt": jwt,
	"r": r,
	"s": s,
	"username": username,
	"ec_x": ec_x,
	"ec_y": ec_y
})

print("registered successfully!")
