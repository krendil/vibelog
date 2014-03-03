module vibelog.dbcontroller;

public import vibelog.post;
public import vibelog.user;

import vibe.core.log;
import vibe.crypto.passwordhash;
import vibe.data.bson;
import vibe.db.mongo.mongo;
import vibe.mail.smtp;
import vibe.stream.memory;
import vibe.templ.diet;

import std.algorithm;
import std.array;
import std.datetime;
import std.exception;
import std.variant;

import core.time;

class DBController {
	private {
		MongoCollection m_users;
		MongoCollection m_posts;
		MongoCollection m_comments;
        MongoCollection m_tokens;
	}

	this(string host, ushort port, string dbname)
	{
		auto db = connectMongoDB(host, port).getDatabase(dbname);
		m_users = db["users"];
		m_posts = db["posts"];
		m_comments = db["comments"];
        m_tokens = db["tokens"];

		// Upgrade post contained comments to their collection
		foreach( p; m_posts.find(["comments": ["$exists": true]], ["comments": 1]) ){
			foreach( c; p.comments ){
				c["_id"] = BsonObjectID.generate();
				c["postId"] = p._id;
				m_comments.insert(c);
			}
			m_posts.update(["_id": p._id], ["$unset": ["comments": 1]]);
		}
	}

	User[string] getAllUsers()
	{
		Bson[string] query;
		User[string] ret;
		foreach( user; m_users.find(query) ){
			auto u = User.fromBson(user);
			ret[u.username] = u;
		}
		if( ret.length == 0 ){
			auto initial_admin = new User;
			initial_admin.username = "admin";
			initial_admin.name = "Default Administrator";
			m_users.insert(initial_admin);
			ret["admin"] = initial_admin;
		}
		return ret;
	}
	
	User getUser(BsonObjectID userid)
	{
		auto userbson = m_users.findOne(["_id": Bson(userid)]);
		return User.fromBson(userbson);
	}

	User getUser(string name)
	{
		auto userbson = m_users.findOne(["username": Bson(name)]);
		if( userbson.isNull() ){
			auto id = BsonObjectID.fromHexString(name);
			logDebug("%s <-> %s", name, id.toString());
			assert(id.toString() == name);
			userbson = m_users.findOne(["_id": Bson(id)]);
		}
		//auto userbson = m_users.findOne(Bson(["name" : Bson(name)]));
		return User.fromBson(userbson);
	}

    bool userExists(string name)
    {
        auto userbson = m_users.findOne(["username": Bson(name)]);
        return !userbson.isNull();
    }

	BsonObjectID addUser(User user)
	{
		auto id = BsonObjectID.generate();
		Bson userbson = user.toBson();
		userbson["_id"] = Bson(id);
		m_users.insert(userbson);
		return id;
	}

	void modifyUser(User user)
	{
		assert(user._id.valid);
		Bson update = user.toBson();
		m_users.update(["_id": Bson(user._id)], update);
	}

	void deleteUser(BsonObjectID id)
	{
		assert(id.valid);
		m_users.remove(["_id": Bson(id)]);
	}


	void getPublicPosts(int nskip, bool delegate(size_t idx, Post post) del)
	{
		Bson[string] query = ["query" : Bson(["isPublic": Bson(true)]), "orderby" : Bson(["_id" : Bson(-1)])];
		foreach( idx, post; m_posts.find(query, null, QueryFlags.None, nskip) ){
			if( !del(idx, Post.fromBson(post)) )
				break;
		}
	}

    int countAllPosts() {
        int cnt;
        getAllPosts(0, (size_t idx, Post post) { if(post.isPublic) {cnt++; return true;} return false; } ); 
        return cnt;
    }

	void getAllPosts(int nskip, bool delegate(size_t idx, Post post) del)
	{
		Bson[string] query;
		Bson[string] extquery = ["query" : Bson(query), "orderby" : Bson(["_id" : Bson(-1)])];
		foreach( idx, post; m_posts.find(extquery, null, QueryFlags.None, nskip) ){
			if( !del(idx, Post.fromBson(post)) )
				break;
		}
	}


	Post getPost(BsonObjectID postid)
	{
		auto postbson = m_posts.findOne(["_id": Bson(postid)]);
		return Post.fromBson(postbson);
	}

	Post getPost(string name)
	{
		auto postbson = m_posts.findOne(["slug": Bson(name)]);
		if( postbson.isNull() )
			postbson = m_posts.findOne(["_id" : Bson(BsonObjectID.fromHexString(name))]);
		return Post.fromBson(postbson);
	}

	bool hasPost(string name)
	{
		return !m_posts.findOne(["slug": Bson(name)]).isNull();

	}

	BsonObjectID addPost(Post post)
	{
		auto id = BsonObjectID.generate();
		Bson postbson = post.toBson();
		postbson["_id"] = Bson(id);
		m_posts.insert(postbson);
		return id;
	}

	void modifyPost(Post post)
	{
		assert(post.id.valid);
		Bson update = post.toBson();
		m_posts.update(["_id": Bson(post.id)], update);
	}

	void deletePost(BsonObjectID id)
	{
		assert(id.valid);
		m_posts.remove(["_id": Bson(id)]);
	}

	Comment[] getComments(BsonObjectID post_id, bool allow_inactive = false)
	{
		Comment[] ret;
		foreach( c; m_comments.find(["postId": post_id]) )
			if( allow_inactive || c.isPublic.get!bool )
				ret ~= Comment.fromBson(c);
		return ret;
	}

	long getCommentCount(BsonObjectID post_id)
	{
		return m_comments.count(["postId": Bson(post_id), "isPublic": Bson(true)]);
	}

	void addComment(BsonObjectID post_id, Comment comment)
	{
		Bson cmtbson = comment.toBson();
		comment.id = BsonObjectID.generate();
		comment.postId = post_id;
		m_comments.insert(comment.toBson());
	}

	void setCommentPublic(BsonObjectID comment_id, bool is_public)
	{
		m_comments.update(["_id": comment_id], ["$set": ["isPublic": is_public]]);
	}

	void deleteNonPublicComments(BsonObjectID post_id)
	{
		m_posts.remove(["postId": Bson(post_id), "isPublic": Bson(false)]);
	}

    void setTokenTTL(Duration ttl) {
        m_tokens.setTTLIndex( [ "created" : 1 ], ttl.total!"seconds" );
    }

    void addAuthToken(string username, string token) {
        //hash token
        string hash = generateSimplePasswordHash(token);
        //store in the db
        Bson doc = Bson.emptyObject();

        doc["created"] = BsonDate(Clock.currTime);
        doc["username"] = username;
        doc["tokenhash"] = hash;
        m_tokens.insert(doc);
    }

    bool checkAuthToken(string username, string token)
    {
        auto results = m_tokens.find(["username" : username]);
        return results
            .map!( bson => (testSimplePasswordHash(bson["tokenhash"].get!string(), token)) )
            .any!("a");
    }
}

private void setTTLIndex(
        MongoCollection coll, int[string] fieldOrders,
        long ttl, IndexFlags flags = IndexFlags.None) 
{
    auto indexname = appender!string();
    bool first = true;
    foreach( f, d; fieldOrders ) {
        if( !first ) indexname.put('_');
        else first = false;
        indexname.put(f);
        indexname.put('_');
        indexname.put(to!string(d));
    }

    import std.string: format;

    Bson[string] doc;
    doc["v"] = 1;
    doc["key"] = serializeToBson(fieldOrders);
    doc["ns"] = format("%s.%s", coll.database.name, coll.name);
    doc["name"] = indexname.data;
    if( flags & IndexFlags.Unique ) doc["unique"] = true;
    if( flags & IndexFlags.DropDuplicates ) doc["dropDups"] = true;
    if( flags & IndexFlags.Background ) doc["background"] = true;
    if( flags & IndexFlags.Sparse ) doc["sparse"] = true;
    doc["expireAfterSeconds"] = ttl;

    if(!coll.database["system.indexes"].find(Bson([ "name" : doc["name"] ])).empty) {
        coll.dropIndexes(indexname.data);
    }
    coll.database["system.indexes"].insert(doc);
}

private Bson dropIndexes(MongoCollection coll, string name) 
{
    debug import std.stdio;

    auto cmd =  Bson.emptyObject();
    cmd["dropIndexes"] = coll.name;
    cmd["index"] = name;
    debug writeln(cmd);

    auto res = coll.database.runCommand(cmd);
    debug writeln(res);
    return res;
}
