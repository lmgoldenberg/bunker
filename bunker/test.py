# Copyright James Connolly 2024
"""
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

from websockets.sync.client import connect
import msgpack
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

challenge = get_random_bytes(32)
h = SHA256.new(challenge)

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
	resp = {
		"signed_data": {
			"r": bytes(resp["Sign"][0]),
			"s": bytes(resp["Sign"][1])
		},
		"ec_point": {
			"x": int.from_bytes(bytes(resp["Sign"][2][0]), "big"),
			"y": int.from_bytes(bytes(resp["Sign"][2][1]), "big")
		}
	}

	signed = resp["signed_data"]["r"] + resp["signed_data"]["s"]

	k = ECC.construct(point_x=resp["ec_point"]["x"], point_y=resp["ec_point"]["y"], curve="p256")
	print(k)

	verifier = DSS.new(k, "fips-186-3")
	verifier.verify(h, signed)
	print("signature is valid!")
