module vibelog.user;

import vibe.crypto.passwordhash;
import vibe.data.bson;
import vibe.textfilter.markdown;
import vibe.textfilter.html;

import std.array;
import std.base64;
import std.conv;
import std.exception;
import std.random;
public import std.datetime;


class User {
	BsonObjectID _id;
	string username;
	string name;

	this()
	{
		_id = BsonObjectID.generate();
	}

	static User fromBson(Bson bson)
	{
		auto ret = new User;
		ret._id = cast(BsonObjectID)bson["_id"];
		ret.username = cast(string)bson["username"];
		ret.name = cast(string)bson["name"];
		return ret;
	}
	
	Bson toBson()
	const {
		Bson[] bgroups;

		Bson[string] ret;
		ret["_id"] = Bson(_id);
		ret["username"] = Bson(username);
		ret["name"] = Bson(name);

		return Bson(ret);
	}
}
