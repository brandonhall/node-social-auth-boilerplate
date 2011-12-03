/**
 * Variables
 */

var express = require('express'),
    util = require('util'),
    mongoose = require('mongoose'),
    mongooseAuth = require('mongoose-auth'),
    mongoStore = require('connect-mongodb'),
    everyauth = require('everyauth'),
    conf = require('./conf'),
    models = require('./models'),
    Schema = mongoose.Schema,
    ObjectId = mongoose.SchemaTypes.ObjectId,
    db,
    User,
    LoginToken,
    app = express.createServer();

/**
 * Model: User
 */

var UserSchema = new Schema({
    role: {type: String, default: 'free'}}
);

UserSchema.plugin(mongooseAuth, {
    everymodule:{
        everyauth:{
            User:function () {
                return User;
            }
        }
    }, facebook:{
        everyauth:{
            myHostname:'http://local.host:3000',
            appId:conf.fb.appId,
            appSecret:conf.fb.appSecret,
            scope:'email',
            redirectPath:'/auth',
            findOrCreateUser:function (sess, accessTok, accessTokExtra, fbUser) {

                var promise = this.Promise(), User = this.User()();

                User.where('google.email', fbUser.email).findOne(function (err, user) {
                    if (err) return promise.fail(err);
                    if (!user) {
                        User.findOne({'fb.id':fbUser.id}, function (err, foundUser) {
                            if (foundUser) {
                                return promise.fulfill(foundUser);
                            }
                            console.log("CREATING");
                            User.createWithFB(fbUser, accessTok, accessTokExtra.expires, function (err, createdUser) {

                                if (err) return promise.fail(err);
                                return promise.fulfill(createdUser);

                            });
                        });
                    } else {
                        assignFbDataToUser(user, accessTok, accessTokExtra, fbUser);
                        user.save(function (err, user) {
                            if (err) return promise.fail(err);
                            promise.fulfill(user);
                        });
                    }
                });

                return promise;
            }
        }
    }, google:{
        everyauth:{
            myHostname:'http://local.host:3000',
            appId:conf.google.appId,
            appSecret:conf.google.appSecret,
            scope:'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',
            redirectPath:'/auth',
            findOrCreateUser:function (sess, accessTok, accessTokExtra, googleUser) {

                var promise = this.Promise(), User = this.User()();

                User.where('fb.email', googleUser.email).findOne(function (err, user) {
                    if (err) return promise.fail(err);
                    if (!user) {
                        User.findOne({'google.email':googleUser.email}, function (err, foundUser) {
                            if (foundUser) {
                                return promise.fulfill(foundUser);
                            }
                            console.log("CREATING");
                            User.createWithGoogleOAuth(googleUser, accessTok, accessTokExtra, function (err, createdUser) {

                                if (err) return promise.fail(err);
                                return promise.fulfill(createdUser);

                            });
                        });
                    } else {
                        assignGoogleDataToUser(user, accessTok, accessTokExtra, googleUser);
                        user.save(function (err, user) {
                            if (err) return promise.fail(err);
                            promise.fulfill(user);
                        });
                    }
                });

                return promise;
            }
        }
    }
});

function assignFbDataToUser(user, accessTok, accessTokExtra, fbUser) {
    user.fb.accessToken = accessTok;
    user.fb.expires = accessTokExtra.expires;
    user.fb.id = fbUser.id;
    user.fb.name.first = fbUser.first_name;
    user.fb.name.last = fbUser.last_name;
    user.fb.name.full = fbUser.name;
    user.fb.alias = fbUser.link.match(/^http:\/\/www.facebook\.com\/(.+)/)[1];
    user.fb.gender = fbUser.gender;
    user.fb.email = fbUser.email;
    user.fb.timezone = fbUser.timezone;
    user.fb.locale = fbUser.locale;
    user.fb.verified = fbUser.verified;
    user.fb.updatedTime = fbUser.updated_time;
}

function assignGoogleDataToUser(user, accessTok, accessTokExtra, googleUser) {
    var expiresDate = new Date;
    expiresDate.setSeconds(expiresDate.getSeconds() + accessTokExtra.expires_in);
    user.google.accessToken = accessTok;
    user.google.refreshToken = accessTokExtra.refreshToken;
    user.google.email = googleUser.email;
    user.google.name = googleUser.name;
    user.google.given_name = googleUser.given_name;
    user.google.family_name = googleUser.family_name;
    user.google.gender = googleUser.gender;
    user.google.picture = googleUser.picture;
    user.google.locale = googleUser.locale;
    user.google.expires = googleUser.expiresDate;
    user.google.id = googleUser.id;
}

mongoose.model('User', UserSchema);
User = mongoose.model('User');

/**
 * Setup
 */

app.configure('development', function () {
    app.use(express.errorHandler({ dumpExceptions:true, showStack:true }));
    everyauth.debug = true;
    app.set('db-uri', 'mongodb://localhost/node-social-auth-development');
});

app.configure('test', function () {
    app.set('db-uri', 'mongodb://localhost/node-social-auth-test');
});

app.configure('production', function () {
    app.set('db-uri', 'mongodb://localhost/node-social-auth-production');
});


app.configure(function () {
    app.set('views', __dirname + '/views');
    app.set('view engine', 'jade');
    app.use(require('stylus').middleware({ src:__dirname + '/public' }));
    db = mongoose.connect(app.set('db-uri'));
    app.use(express.bodyParser());
    app.use(express.methodOverride());
    app.use(express.cookieParser());
    app.use(express.session({ store:mongoStore(app.set('db-uri')), secret:'YOUR SECRET KEY' }));
    app.use(express.logger({ format:'\x1b[1m:method\x1b[0m \x1b[33m:url\x1b[0m :response-time ms' }));
    app.use(mongooseAuth.middleware());
    app.use(express.static(__dirname + '/public'));
});

mongooseAuth.helpExpress(app);

/**
 * Functions
 */

models.defineModels(mongoose, function () {
    app.LoginToken = LoginToken = mongoose.model('LoginToken');
})

function authenticateFromLoginToken(req, res, next) {
    var cookie = JSON.parse(req.cookies.logintoken);

    LoginToken.findOne({ userid:cookie.userid,
        series:cookie.series,
        token:cookie.token }, (function (err, token) {
        if (!token) {
            res.redirect('/new');
            return;
        }

        User.findOne({ _id:token.userid }, function (err, user) {
            if (user) {
                //console.log(user);
                req.session.user_id = user.id;
                req.currentUser = user;

                token.token = token.randomToken();
                token.save(function () {
                    res.cookie('logintoken', token.cookieValue, { expires:new Date(Date.now() + 2 * 604800000), path:'/' });
                    next();
                });
            } else {

                res.redirect('/new');
            }
        });
    }));
}


function loadUser(req, res, next) {
    if (req.session.user_id) {
        User.findById(req.session.user_id, function (err, user) {
            if (user) {
                req.currentUser = user;
                next();
            } else {
                res.redirect('/new');
            }
        });

    } else if (req.cookies.logintoken) {
        authenticateFromLoginToken(req, res, next);
    } else {
        res.redirect('/new');
    }
}

/**
 * Routes
 */

app.get('/', loadUser, function (req, res) {
    res.redirect('/auth');
});

app.get('/bye', loadUser, function (req, res) {
    if (req.session) {
        LoginToken.remove({ userid:req.session.user_id }, function () {
        });
        res.clearCookie('logintoken');
        req.session.destroy(function () {
        });
    }
    res.redirect('/new');
});

app.get('/auth', function (req, res) {
    if (req.cookies.logintoken) {
        res.redirect('/app');
    } else {
        var loginToken = new LoginToken({ userid:req.user.id});
        loginToken.save(function () {
            res.cookie('logintoken', loginToken.cookieValue, { expires:new Date(Date.now() + 2 * 604800000), path:'/' });
            res.redirect('/app');
        });

    }
});

app.get('/app', loadUser, function (req, res) {
    res.render('app', { title:'Node-Social-Auth'});
});

app.get('/new', function (req, res) {
    res.render('new', { title:'Node-Social-Auth' });
});

app.dynamicHelpers({
    fbUser:function (req, res) {
        if (req.currentUser) {
            if (req.currentUser.fb.id) {
                return req.currentUser;
            }
        }
    },
    googleUser:function (req, res) {
        if (req.currentUser) {
            if (req.currentUser.google.email) {
                return req.currentUser;
            }
        }
    },
    bothUser:function (req, res) {
        if (req.currentUser) {
            if (req.currentUser.google.email && req.currentUser.fb.id) {
                return req.currentUser;
            }
        }
    }
});

// Error handling
function NotFound(msg) {
    this.name = 'NotFound';
    Error.call(this, msg);
    Error.captureStackTrace(this, arguments.callee);
}

util.inherits(NotFound, Error);

app.get('/404', function (req, res) {
    throw new NotFound;
});

app.get('/500', function (req, res) {
    throw new Error('An expected error');
});

app.get('/bad', function (req, res) {
    unknownMethod();
});

app.error(function (err, req, res, next) {
    if (err instanceof NotFound) {
        res.render('404', { status:404 });
    } else {
        next(err);
    }
});

/**
 * Launch
 */


if (!module.parent) {
    app.listen(3000);
    console.log("Express server listening on port %d in %s mode", app.address().port, app.settings.env);
    console.log('Express %s, Mongoose %s', express.version, mongoose.version);
}