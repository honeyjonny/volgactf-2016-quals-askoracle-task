#coding: UTF-8

from bson import ObjectId
from datetime import datetime

class MongoDbModelsMiddleware(object):
	async def find_users(self):
		return [ self.map_doc_to_dto(u) for u in self.application.db.users.find( { }, { "pass": 0 } ) ]

	async def create_user(self, user):
		return self.application.db.users.save(user)

	async def find_user_byname(self, name):
		return self.application.db.users.find( {"name": name}, { "pass": 0 } )

	async def find_user_byId_async(self, userId):
		uid = ObjectId(userId)
		user = self.application.db.users.find( { "_id": uid }, { "pass": 0 } )
		if user.count() == 1:
			return user[0]
		else:
			return None

	async def find_user_by_logindata(self, userDto):
		return self.application.db.users.find( userDto, { "pass": 0 } )

	async def save_cookie_for_user(self, userDoc, cookie):
		return self.application.db.tokens.save( { "user_id": userDoc["_id"], "value": cookie } ) 

	async def delete_prev_tokens(self, userDoc):
		deleted = self.application.db.tokens.delete_many(  { "user_id": userDoc["_id"] } )
		return deleted.deleted_count

	async def find_user_by_token(self, token):
		cur = self.application.db.tokens.find( { "value" : token } )
		if cur.count() == 1:
			token_doc = cur[0]
			userCur = self.application.db.users.find( {"_id": token_doc["user_id"] }, { "pass": 0 }  )
			if userCur.count() == 1:			
				user = userCur[0]
				return user		
		return None

	def map_doc_to_dto(self, doc):
		doc["_id"] = str(doc["_id"])
		return doc

	async def create_note_for_usr_async(self, userDoc, ciphertext):
		created = datetime.isoformat(datetime.now())
		return self.application.db.notes.save( { "user_id": userDoc["_id"], "content" : ciphertext, "created": created } )

	async def find_notes_for_user_async(self, userDoc):
		return self.application.db.notes.find( { "user_id": userDoc["_id"] } )

	async def find_note_byId_async(self, noteId):
		nid = ObjectId(noteId)
		return self.application.db.notes.find( { "_id": nid } )