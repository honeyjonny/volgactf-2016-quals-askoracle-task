import tornado.web
import tornado.websocket
import tornado.escape

from crypto import DESCryptor
from hashlib import md5, sha512
from time import time
from bson import ObjectId
from dbprovider import MongoDbModelsMiddleware


class Basehandler(tornado.web.RequestHandler, MongoDbModelsMiddleware):

	@property	
	def current_token(self):
		if not hasattr(self, "_current_token"):
			self._current_token = self.get_cookie("_la_tokionare")
		return self._current_token

	@current_token.setter
	def current_token(self, value):
		self._current_token = value

	@property
	def current_username(self):
		if self.current_user == None:
			return None
		else:
			return self.current_user["name"]

	async def generate_key_iv_for_usr_async(self, user):

		def get_key_iv(string):
			return string[:8].encode('ascii'), string[-8:].encode('ascii')

		userDto = user
		salt = self.application.SALT

		digest = sha512()
		digest.update(userDto["name"].encode("utf-8"))
		#digest.update(userDto["pass"].encode("utf-8"))
		digest.update( str( userDto["_id"] ).encode("utf-8") )
		digest.update( salt.encode("utf-8") )
		hexcode = digest.hexdigest()
		return get_key_iv(hexcode)


	async def generate_session_for_user(self, userDto):
		digest = md5()

		salt = self.application.SALT

		digest.update(userDto["name"].encode("utf-8"))
		#digest.update(userDto["pass"].encode("utf-8"))
		digest.update( str( userDto["_id"] ).encode("utf-8") )
		digest.update( salt.encode("utf-8") )
		digest.update( str( time() ).encode("utf-8") )		
		return digest.hexdigest()

	async def prepare(self):
		token = self.current_token

		if token == None:
			self.current_user = None;

		else:
			user = await self.find_user_by_token(token)
			if user == None:
				return

			else:
				self.current_user = user


class RegisteredOnlyHandler(Basehandler):
	async def prepare(self):
		await super().prepare()

		if self.current_user == None and self.current_token == None:
			self.set_status(401)
			self.write({"error": "unauthorized"})
			self.finish()


class ApiUsershandler(Basehandler):
	async def get(self):
		resp = await self.find_users()
		if self.current_user:
			usr = self.map_doc_to_dto(self.current_user)
		else:
			usr = "none"
		self.write( { "current_user": usr, "users": resp } )


class MainHandler(Basehandler):
	async def get(self):
		resp = await self.find_users()

		if self.current_user == None:
			uid = None
		else:
			uid = str(self.current_user["_id"] )

		self.render("index.html", users = resp, current_username = self.current_username, cur_uid = uid )


class RegisterHandler(Basehandler):
	async def get(self):
		self.render("form.html", action="register", current_username = self.current_username )

	async def post(self):
		username = self.get_argument( "username" )
		password = self.get_argument( "password" )

		if (len(username) > 256) or (len(password)>256):
			self.set_status(400)
			self.write({"error":"do you really need so long nickname or password? lol"})
			self.finish()
			return

		cursor = await self.find_user_byname(username)
		count = cursor.count()

		if count > 0:
			self.set_status(409)
			self.write({"error": "user already exists"})
			self.finish()
			return

		usr = {"name":username, "pass": password}

		uid = await self.create_user(usr)

		self.set_status(201)
		self.redirect("/login")


class LoginHandler(Basehandler):
	async def get(self):
		self.render("form.html", action="login", current_username = self.current_username )

	async def post(self):

		username = self.get_argument( "username" )
		password = self.get_argument( "password" )

		if (len(username) > 256) or (len(password)>256):
			self.set_status(400)
			self.write({"error":"ahahaha, off mark. lol"})
			self.finish()
			return
		
		usr = {"name":username, "pass": password}

		cursor = await self.find_user_by_logindata(usr)
		count = cursor.count()

		if count == 1:

			user = cursor[0]
			#print(user)

			cookie = await self.generate_session_for_user(user)

			await self.delete_prev_tokens(user)
			await self.save_cookie_for_user(user, cookie)

			self.set_status(202)
			self.set_cookie("_la_tokionare", cookie)
			self.redirect("/")
			return
		else:
			self.set_status(404)
			self.write({ "status": "not found this user", "user": usr})


class Logouthandler(RegisteredOnlyHandler):
	async def get(self):
		user = self.current_user
		await self.delete_prev_tokens(user)

		self.set_status(303)
		self.redirect("/")


class NotesHandler(RegisteredOnlyHandler):

	def note_to_dto(self, note):
		note["_id"] = str(note["_id"])
		note["user_id"] = str(note["user_id"])
		return note

	async def get(self, userId):
		user = await self.find_user_byId_async(userId)

		if user == None:
			self.set_status(404)
			self.write({ "error": "not found user with that id: %s" % userId })
			self.finish()
			return

		notes = await self.find_notes_for_user_async(user)

		notesDto = [ self.note_to_dto(note) for note in notes ]

		if self.current_user == None:
			uid = None
		else:
			uid = str(self.current_user["_id"] )

		self.render("notes.html", notes = notesDto, current_username = self.current_username, cur_uid = uid )


	async def post(self, userId):
		if ObjectId(userId) != self.current_user["_id"]:
			self.set_status(409)
			self.write({"error":"off the mark :) "})
			self.finish()
			return

		url = "/home/" + str(self.current_user["_id"])

		noteContent = self.get_argument( "noteContent" )

		if (noteContent == None) or (len(noteContent) == 0):
			self.set_status(307)
			self.write( { "error": "form invalid" } )	
			self.redirect(url)
			return

		if len(noteContent) > 256:
			self.set_status(307)
			self.write( { "error": "too many words, brrr" } )	
			self.finish()
			return			


		key, iv = await self.generate_key_iv_for_usr_async(self.current_user)

		dc = DESCryptor(key, iv)
		ciphertext = dc.encrypt(noteContent)

		await self.create_note_for_usr_async(self.current_user, ciphertext)

		self.set_status(201)
		self.redirect(url)


class NotesDecryptHandler(RegisteredOnlyHandler):

	async def get(self, userId, ciphertext):

		user = await self.find_user_byId_async(userId)

		if user == None:
			self.set_status(404)
			self.write({ "error": "not found user with that id: %s" % userId })
			self.finish()
			return

		key, iv = await self.generate_key_iv_for_usr_async(user)

		dc = DESCryptor(key, iv)

		try:
			plaintext = dc.decrypt(ciphertext)
		except Exception as ex:
			self.set_status(500)
			self.write({"error": "%s" % ex})
			self.finish()
			return

		if self.current_user["_id"] == ObjectId(userId):
			self.set_status(200)
			self.write({"data": "%s" % plaintext})
			self.finish()
			return
		else:
			self.set_status(409)
			self.write({"error": "sorry, this is not your secure note"})
			self.finish()
			return