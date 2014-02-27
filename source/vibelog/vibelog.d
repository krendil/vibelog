module vibelog.vibelog;

import vibelog.dbcontroller;
import vibelog.rss;

import vibe.core.log;
import vibe.crypto.cryptorand;
import vibe.crypto.passwordhash;
import vibe.db.mongo.connection;
import vibe.http.auth.basic_auth;
import vibe.http.client;
import vibe.http.router;
import vibe.inet.url;
import vibe.templ.diet;

import std.base64;
import std.conv;
import std.datetime;
import std.exception;
import std.string;
import std.typecons;

debug {
    import std.stdio;
}

class VibeLogSettings {
	string databaseHost = "localhost";
	ushort databasePort = MongoConnection.defaultPort;
	string databaseName = "vibelog";
	int postsPerPage = 4;
	URL siteUrl = URL.parse("http://localhost:8080/");
	string function(string)[] textFilters;
}

void registerVibeLog(alias config)(VibeLogSettings settings, URLRouter router)
{
	new VibeLog!config(settings, router);
}

class VibeLog(alias config) {
	private {
		DBController m_db;
		string m_subPath;
		VibeLogSettings m_settings;
	}

	this(VibeLogSettings settings, URLRouter router)
	{
		m_settings = settings;
		m_db = new DBController(settings.databaseHost, settings.databasePort, settings.databaseName);

		m_subPath = settings.siteUrl.path.toString();

		enforce(m_subPath.startsWith("/") && m_subPath.endsWith("/"), "All local URLs must start with and end with '/'.");


		//
		// public pages
		//
		if( m_subPath.length > 1 ) router.get(m_subPath[0 .. $-1], staticRedirect(m_subPath));
		router.get(m_subPath, &showPostList);
		router.get(m_subPath ~ "posts/:postname", &showPost);
		router.post(m_subPath ~ "posts/:postname/post_comment", &postComment);
		router.post(m_subPath ~ "markup", &markup);

		router.get(m_subPath ~ "sitemap.xml", &sitemap);

		//
		// restricted pages
		//
		router.get(m_subPath ~ "manage",                      auth(&showAdminPanel));

		router.get(m_subPath ~ "users/",                      auth(&showUserList));
		router.get(m_subPath ~ "users/:username/edit",        auth(&showUserEdit));
		router.post(m_subPath ~ "users/:username/put",        auth(&putUser));
		router.post(m_subPath ~ "users/:username/delete",     auth(&deleteUser));
		router.post(m_subPath ~ "add_user",                   auth(&addUser));

		router.get(m_subPath ~ "posts/",                      auth(&showEditPosts));
		router.get(m_subPath ~ "posts/:postname/edit",        auth(&showEditPost));
		router.post(m_subPath ~ "posts/:postname/put",        auth(&putPost));
		router.post(m_subPath ~ "posts/:postname/delete",     auth(&deletePost));
		router.post(m_subPath ~ "posts/:postname/set_comment_public", auth(&setCommentPublic));
		router.get(m_subPath ~ "make_post",                   auth(&showMakePost));
		router.post(m_subPath ~ "make_post",                  auth(&putPost));

        //
        // IndieAuth redirect location
        //
        router.get(m_subPath ~ "authed/:path",                &authed);
        router.get(m_subPath ~ "authed/",        (scope HTTPServerRequest req, scope HTTPServerResponse res) {
                                                                req.params["path"] = "";
                                                                authed(req, res);
                                                                });

        m_db.setTokenTTL(days(config.sessionLength));
	}

	int getPageCount()
	{
		int cnt = m_db.countAllPosts();
		return (cnt + m_settings.postsPerPage - 1) / m_settings.postsPerPage;
	}

	Post[] getPostsForPage(int n)
	{
		Post[] ret;
		try {
			size_t cnt = 0;
			m_db.getPublicPosts(n*m_settings.postsPerPage, (size_t i, Post p){
				ret ~= p;
				if( ++cnt >= m_settings.postsPerPage )
					return false;
				return true;
			});
		} catch( Exception e ){
			auto p = new Post;
			p.header = "ERROR";
			p.subHeader = e.msg;
			ret ~= p;
		}
		return ret;
	}

	Post[] getRecentPosts()
	{
		Post[] ret;
		m_db.getPublicPosts(0, (i, p){
			if( i > 20 ) return false;
			ret ~= p;
			return true;
		});
		return ret;
	}

	string getShowPagePath(int page)
	{
		return m_subPath ~ "?page=" ~ to!string(page+1);
	}

	//
	// public pages
	//

	protected void showPostList(HTTPServerRequest req, HTTPServerResponse res)
	{
		struct ShowPostListInfo {
			string rootDir;
			User[string] users;
			string function(string)[] textFilters;
			int pageNumber = 0;
			int pageCount;
			Post[] posts;
			long[] commentCount;
			Post[] recentPosts;
		}
		
		ShowPostListInfo info;
		info.rootDir = m_subPath; // TODO: use relative path
		info.users = m_db.getAllUsers();
		info.textFilters = m_settings.textFilters;
		info.pageCount = getPageCount();
		if( auto pp = "page" in req.query ) info.pageNumber = to!int(*pp)-1;
		info.posts = getPostsForPage(info.pageNumber);
		foreach( p; info.posts ) info.commentCount ~= m_db.getCommentCount(p.id);
		info.recentPosts = getRecentPosts();

		//res.render!("vibelog.postlist.dt", req, posts, pageNumber, pageCount)(res.bodyWriter);
		res.renderCompat!("vibelog.postlist.dt",
			HTTPServerRequest, "req",
            typeof(config), "config",
			ShowPostListInfo*, "info")
			(req, config, &info);
	}

	protected void showPost(HTTPServerRequest req, HTTPServerResponse res)
	{
		struct ShowPostInfo {
			string rootDir;
			User[string] users;
			string function(string)[] textFilters;
			Post post;
			Comment[] comments;
			Post[] recentPosts;
		}

		ShowPostInfo info;
		info.rootDir = m_subPath; // TODO: use relative path
		info.users = m_db.getAllUsers();
		info.textFilters = m_settings.textFilters;
		try info.post = m_db.getPost(req.params["postname"]);
		catch(Exception e){ return; } // -> gives 404 error
		info.comments = m_db.getComments(info.post.id);
		info.recentPosts = getRecentPosts();
		
		//res.render!("vibelog.post.dt", req, users, post, textFilters);
		res.renderCompat!("vibelog.post.dt",
			HTTPServerRequest, "req",
            typeof(config), "config",
			ShowPostInfo*, "info")
			(req, config, &info);
	}

	protected void postComment(HTTPServerRequest req, HTTPServerResponse res)
	{
		auto post = m_db.getPost(req.params["postname"]);
		enforce(post.commentsAllowed, "Posting comments is not allowed for this article.");

		auto c = new Comment;
		c.isPublic = true;
		c.date = Clock.currTime().toUTC();
		c.authorName = req.form["name"];
		c.authorMail = req.form["email"];
		c.authorHomepage = req.form["homepage"];
		c.authorIP = req.peer;
		if( auto fip = "X-Forwarded-For" in req.headers ) c.authorIP = *fip;
		if( c.authorHomepage == "http://" ) c.authorHomepage = "";
		c.content = req.form["message"];
		m_db.addComment(post.id, c);

		res.redirect(m_subPath ~ "posts/"~post.name);
	}


	protected void markup(HTTPServerRequest req, HTTPServerResponse res)
	{
		auto post = new Post;
		post.content = req.form["message"];
		res.writeBody(post.renderContentAsHtml(m_settings.textFilters), "text/html");
	}

	protected void sitemap(HTTPServerRequest req, HTTPServerResponse res)
	{
		res.contentType = "application/xml";
		res.bodyWriter.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
		res.bodyWriter.write("<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n");
		void writeEntry(string[] parts...){
			res.bodyWriter.write("<url><loc>");
			res.bodyWriter.write(m_settings.siteUrl.toString());
			foreach( p; parts )
				res.bodyWriter.write(p);
			res.bodyWriter.write("</loc></url>\n");
		}

		// home page
		writeEntry();

		res.bodyWriter.write("</urlset>\n");
		res.bodyWriter.flush();
	}

	protected HTTPServerRequestDelegate auth(void delegate(HTTPServerRequest, HTTPServerResponse, User[string], User) del)
	{
		return (HTTPServerRequest req, HTTPServerResponse res)
		{
			User[string] users = m_db.getAllUsers();
			bool testauth(string user, string password)
			{
				auto pu = user in users;
				if( pu is null ) return false;
				return testSimplePasswordHash(pu.password, password);
			}
			string username = performBasicAuth(req, res, "VibeLog admin area", &testauth);
			auto pusr = username in users;
			assert(pusr, "Authorized with unknown username !?");

            if("auth" in req.cookies) {
                string[] creds = split(req.cookies["auth"], ";");
                bool tokenOk = m_db.checkAuthToken(creds[0], creds[1]);
                logInfo("Authentication for user %s %s", creds[0], tokenOk ? "successful" : "failed");
            } else {
                logInfo("Authcookie not found");
            }

			del(req, res, users, *pusr);
		};
	}

	protected void showAdminPanel(HTTPServerRequest req, HTTPServerResponse res, User[string] users, User loginUser)
	{
		res.renderCompat!("vibelog.admin.dt",
			HTTPServerRequest, "req",
            typeof(config), "config",
			User[string], "users",
			User, "loginUser")
			(req, config, users, loginUser);
	}

	//
	// Users
	//

	protected void showUserList(HTTPServerRequest req, HTTPServerResponse res, User[string] users, User loginUser)
	{
		res.renderCompat!("vibelog.edituserlist.dt",
			HTTPServerRequest, "req",
            typeof(config), "config",
			User, "loginUser",
			User[string], "users")
			(req, config, loginUser, users);
	}

	protected void showUserEdit(HTTPServerRequest req, HTTPServerResponse res, User[string] users, User loginUser)
	{
		User user = m_db.getUser(req.params["username"]);
		res.renderCompat!("vibelog.edituser.dt",
			HTTPServerRequest, "req",
            typeof(config), "config",
			User, "loginUser",
			User, "user")
			(req, config, loginUser, user);
	}

	protected void putUser(HTTPServerRequest req, HTTPServerResponse res, User[string] users, User loginUser)
	{
		auto id = req.form["id"];
		User usr;
		if( id.length > 0 ){
			enforce(loginUser.isUserAdmin() || req.form["username"] == loginUser.username,
				"You can only change your own account.");
			usr = m_db.getUser(BsonObjectID.fromHexString(id));
			enforce(usr.username == req.form["username"], "Cannot change the user name!");
		} else {
			enforce(loginUser.isUserAdmin(), "You are not allowed to add users.");
			usr = new User;
			usr.username = req.form["username"];
			foreach( u; users )
				enforce(u.username != usr.username, "A user with the specified user name already exists!");
		}
		enforce(req.form["password"] == req.form["passwordConfirmation"], "Passwords do not match!");

		usr.name = req.form["name"];
		usr.email = req.form["email"];

		if( req.form["password"].length || req.form["passwordConfirmation"].length ){
			enforce(loginUser.isUserAdmin() || testSimplePasswordHash(req.form["oldPassword"], usr.password), "Old password does not match.");
			usr.password = generateSimplePasswordHash(req.form["password"]);
		}

		if( loginUser.isUserAdmin() ){
			usr.groups = null;
			foreach( k, v; req.form ){
				if( k.startsWith("group_") )
					usr.groups ~= k[6 .. $];
			}
		}

		if( id.length > 0 ){
			m_db.modifyUser(usr);
		} else {
			usr._id = m_db.addUser(usr);
		}

		if( loginUser.isUserAdmin() ) res.redirect(m_subPath~"users/");
		else res.redirect(m_subPath~"manage");
	}

	protected void deleteUser(HTTPServerRequest req, HTTPServerResponse res, User[string] users, User loginUser)
	{
		enforce(loginUser.isUserAdmin(), "You are not authorized to delete users!");
		enforce(loginUser.username != req.params["username"], "Cannot delete the own user account!");
		foreach( usr; users )
			if( usr.username == req.params["username"] ){
				m_db.deleteUser(usr._id);
				res.redirect(m_subPath ~ "users/");
				return;
			}
		enforce(false, "Unknown user name.");
	}

	protected void addUser(HTTPServerRequest req, HTTPServerResponse res, User[string] users, User loginUser)
	{
		enforce(loginUser.isUserAdmin(), "You are not authorized to add users!");
		string uname = req.form["username"];
		if( uname !in users ){
			auto u = new User;
			u.username = uname;
			m_db.addUser(u);
		}
		res.redirect(m_subPath ~ "users/" ~ uname ~ "/edit");
	}

	//
	// Posts
	//

	protected void showEditPosts(HTTPServerRequest req, HTTPServerResponse res, User[string] users, User loginUser)
	{
		Post[] posts;
		m_db.getAllPosts(0, (size_t idx, Post post){
			if( loginUser.isPostAdmin() || post.author == loginUser.username )
			{
				posts ~= post;
			}
			return true;
		});
		logInfo("Showing %d posts.", posts.length);
		//parseJadeFile!("vibelog.postlist.dt", req, posts, pageNumber, pageCount)(res.bodyWriter);
		res.renderCompat!("vibelog.editpostslist.dt",
			HTTPServerRequest, "req",
            typeof(config), "config",
			User[string], "users",
			User, "loginUser",
			Post[], "posts")
			(req, config, users, loginUser, posts);
	}

	protected void showMakePost(HTTPServerRequest req, HTTPServerResponse res, User[string] users, User loginUser)
	{
		Post post;
		Comment[] comments;
		res.renderCompat!("vibelog.editpost.dt",
			HTTPServerRequest, "req",
            typeof(config), "config",
			User[string], "users",
			User, "loginUser",
			Post, "post",
			Comment[], "comments")
			(req, config, users, loginUser, post, comments);
	}

	protected void showEditPost(HTTPServerRequest req, HTTPServerResponse res, User[string] users, User loginUser)
	{
		auto post = m_db.getPost(req.params["postname"]);
		auto comments = m_db.getComments(post.id, true);
		res.renderCompat!("vibelog.editpost.dt",
			HTTPServerRequest, "req",
            typeof(config), "config",
			User[string], "users",
			User, "loginUser",
			Post, "post",
			Comment[], "comments")
			(req, config, users, loginUser, post, comments);
	}

	protected void deletePost(HTTPServerRequest req, HTTPServerResponse res, User[string] users, User loginUser)
	{
		auto id = BsonObjectID.fromHexString(req.form["id"]);
		m_db.deletePost(id);
		res.redirect(m_subPath ~ "posts/");
	}

	protected void setCommentPublic(HTTPServerRequest req, HTTPServerResponse res, User[string] users, User loginUser)
	{
		auto id = BsonObjectID.fromHexString(req.form["id"]);
		m_db.setCommentPublic(id, to!int(req.form["public"]) != 0);
		res.redirect(m_subPath ~ "posts/"~req.params["postname"]~"/edit");
	}

	protected void putPost(HTTPServerRequest req, HTTPServerResponse res, User[string] users, User loginUser)
	{
		auto id = req.form["id"];
		Post p;
		if( id.length > 0 ){
			p = m_db.getPost(BsonObjectID.fromHexString(id));
			enforce(req.params["postname"] == p.name, "URL does not match the edited post!");
		} else {
			p = new Post;
			p.date = Clock.currTime().toUTC();
		}

		p.isPublic = ("isPublic" in req.form) !is null;
		p.commentsAllowed = ("commentsAllowed" in req.form) !is null;
		p.author = req.form["author"];
		p.date = SysTime.fromSimpleString(req.form["date"]);
		p.slug = req.form["slug"].length ? req.form["slug"] : makeSlugFromHeader(req.form["header"]);
		p.headerImage = req.form["headerImage"];
		p.header = req.form["header"];
		p.subHeader = req.form["subHeader"];
		p.content = req.form["content"];

		enforce(!m_db.hasPost(p.slug) || m_db.getPost(p.slug).id == p.id, "Post slug is already used for another article.");

		if( id.length > 0 ){
			m_db.modifyPost(p);
			req.params["postname"] = p.name;
		} else {
			p.id = m_db.addPost(p);
		}
		res.redirect(m_subPath~"posts/");
	}


    protected void authed(HTTPServerRequest req, HTTPServerResponse res) {
        //Authenticate token with IndieAuth
        string token = req.query["token"];
        string me = req.query["me"];

        HTTPClientResponse verRes = requestHTTP(
                format("https://indieauth.com/verify?token=%s", token),
                (scope HTTPClientRequest req) {
                    req.method = HTTPMethod.GET;
                });

        Json result = verRes.readJson();
        if(result["me"] == me) {
            logInfo("Authenticated as %s with token %s", me, token);
        } else {
            logWarn("Authentication failed for %s token %s", me, token);
            logWarn("IndieAuth returned %s", result.toString());
            res.redirect(format("http://%s/%s", req.host, req.params["path"]), 401);
            return;
        }

        //Store token
            //Generate token
        ubyte[8] rawToken;
        auto rng = scoped!SystemRNG();
        rng.read(rawToken);
        string newToken = Base64.encode(rawToken).assumeUnique;

            //Store token
        Cookie authCookie = new Cookie();
        with(authCookie) {
            domain = req.host;
            path = "/";
            httpOnly = true;
            expires = (Clock.currTime(UTC()) + config.sessionLength.days()).toCookieString();
            value = format("%s;%s", me, newToken);
        }
        res.cookies["auth"] = authCookie;

        m_db.addAuthToken(me, newToken);
        logInfo("Generated session token for %s: %s", me, newToken);

        //Redirect to site
        res.redirect(format("http://%s/%s", req.host, req.params["path"]), 303);
    }
}

private string toCookieString(SysTime time) {
    enum string[7] dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    enum string[13] monthNames = ["ERR", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    return format("%s, %s %s %s %s:%s:%s GMT",
            dayNames[time.dayOfWeek], time.day, monthNames[time.month], time.year,
            time.hour, time.minute, time.second);

}
