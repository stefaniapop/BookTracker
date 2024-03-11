const express = require('express');
const bcrypt = require('bcryptjs');
const mysql = require('mysql');
const multer = require('multer');
const path = require('path');
const session = require('express-session');

const db = mysql.createConnection({
    host : '127.0.0.1',
    user : 'root',
    password : '',
    database : 'bookapp'
});
db.connect((err) => {
    if(err) throw err;
    else console.log('Connected!');
});

const storage = multer.diskStorage({
    destination: './public/uploads/books',
    filename: function(re, file, cb){
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname)); 
    }
});

const upload = multer({
    storage: storage,
    limits:{files: 1, fileSize: 1024 * 1024}, // 1 file, 1MB max file size
    fileFilter:  function(req, file, cb){
        checkFileType(file, cb);
    }
}).single('coperta');

function checkFileType(file, cb) {
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);

    if(mimetype && extname) {
        return cb(null, true);
    } else {
        cb('Error: Images only');
    }
}

const time = 1000 * 60 * 60 * 2;
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + "/public"));
app.use(express.static(__dirname + '/node_modules/bootstrap/dist'));
app.use(express.static(__dirname + '/node_modules/bootstrap/js/dist'));

app.use(session({
    name: 'session',
    secret: 'cheia secreta',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: time,
        sameSite: true
    }
}))

app.set('view engine', 'ejs');

const redirectLogin = (req, res, next) => {
    if(!req.session.idUser) {
        res.redirect('/');
    } else {
        next()
    }
}

const redirectHome = (req, res, next) => {
    if(req.session.idUser && req.session.role === 'USER') {
        res.redirect('/home');
    } else {
        next()
    }
}

const redirectAdmin = (req, res, next) => {
    if(req.session.idUser && req.session.role === 'ADMIN') {
        res.redirect('/admin');
    } else {
        next()
    }
}

app.use((req, res, next) => {
    const { idUser, username } = req.session;
    if (idUser) {
        res.locals.user = idUser;
        res.locals.username = username;
    }
    next()
})

app.get('/', redirectHome, redirectAdmin, (req, res) => {
    console.log(req.session);
    res.render('index.ejs');
})

app.post('/signin', (req, res) => {
    db.query('SELECT * FROM users WHERE email = (?)', req.body.email, (err,user) => {
        if (err) { res.status(400).json('wrong credentials'); }
        const valid = bcrypt.compareSync(req.body.password, user[0].password_hash);
        if (valid) {
            db.query('SELECT * FROM users WHERE email = (?)', req.body.email, (err, user) => {
                if (err) { res.status(400).json('unable to get user') }
                else {
                    if (user[0].user_role === 'ADMIN') {
                        req.session.idUser = user[0].id_user;
                        req.session.role = user[0].user_role;
                        req.session.username = user[0].username;
                        console.log(session);
                        res.redirect('/admin');
                    }
                    else {
                        req.session.idUser = user[0].id_user;
                        req.session.role = user[0].user_role;
                        req.session.username = user[0].username;
                        console.log(session);
                        res.redirect('/home');
                    }
                }
            })}
        else { res.status(400).json('wrong credentials'); }
    })
})

app.post('/register', (req, res) => {
    let password = req.body.reg_password;
    const hash = bcrypt.hashSync(password);
    let data = { 
        username: req.body.reg_username, 
        email: req.body.reg_email,
        password_hash: hash,
        user_role: 'USER',
        joined: new Date() 
    }
    db.query('INSERT INTO users SET ?', data, (err) => {
        if(err) {res.status(400).json('')}
        else {res.redirect('/');}
    })
});

app.get('/deconectare', redirectLogin, (req, res) => {
    req.session.destroy(err => {
        if(err) {
            return res.redirect('/home');
        }
        res.redirect('/');
    })
})

app.get('/home', redirectLogin, redirectAdmin, (req, res) => {
    const { user, username } = res.locals
    console.log("Home user: ", user);
    console.log(req.session);
    let carti = [];
    db.query('SELECT * FROM carti LEFT JOIN carte_autor ON carti.id_carte = carte_autor.id_carte LEFT JOIN autori ON autori.id_autor = carte_autor.id_autor', (err, results) => {
        if (err) {
            res.status(400).json('can\'t load');
        }
        else {
            results = Object.values(JSON.parse(JSON.stringify(results)));
            console.log(results);
            carti = [...results];
            db.query('SELECT * FROM carti_users LEFT JOIN carti ON carti.id_carte = carti_users.id_carte WHERE id_user = ? AND id_eticheta = ?', [user, 3], (err, results) => {
                if (err) {
                    res.status(400).json('can\'t load');
                }
                else {
                    results = Object.values(JSON.parse(JSON.stringify(results)))
                    console.log(results);
                    res.render('home.ejs', { carti: carti, lectura: results, username: username });
                }
            });
        }
    });
});

app.post('/actualizarePagina', (req, res) => {
    let data = {
        id_user: res.locals.user,
        id_carte: req.body.id_carte,
        id_eticheta: 3
    }
    console.log(data);
    let pagina = req.body.pagina;
    console.log(pagina);
    db.query('UPDATE carti_users SET pagina_curenta = ? WHERE id_user = ? AND id_carte = ? AND id_eticheta = ?',
     [pagina, data.id_user, data.id_carte, data.id_eticheta], (err) => {
        if(err) {res.status(400).json('unable to update')}
        else {res.redirect('back')}
    });
});

app.post('/finalCarte', (req, res) => {
    let data = {
        id_user: res.locals.user,
        id_carte: req.body.id_carte,
        id_eticheta: 3
    }
    console.log(data);
    let nouaEticheta = 1;
    let pagina_curenta = null;
    db.query('UPDATE carti_users SET id_eticheta = ?, pagina_curenta = ? WHERE id_user = ? AND id_carte = ? AND id_eticheta = ?', [nouaEticheta, pagina_curenta, data.id_user, data.id_carte, data.id_eticheta], (err) => {
        if(err) {res.status(400).json('unable to update')}
        else {res.redirect('back')}
    });
})

app.get('/carte/:id', redirectLogin, redirectAdmin, (req, res) => {
    let { id } = req.params;
    const { username } = res.locals
    console.log(id);
    let gen = [];
    let carte = {};
    let autor = {};
    let rezultat = {};
    let reviews = [];
    let toRead = {value: false};
    let read = {value: false}; 
    let reading = {value: false};

    db.beginTransaction((err) => {
        if (err) {
            res.status(400).json('error');
        }
        else {
            db.query('SELECT * FROM carti WHERE id_carte = ?', id, (err, results) => {
                if (err) { res.status(400).json('not found'); }
                else {
                    carte = Object.values(JSON.parse(JSON.stringify(results)))

                    db.query('SELECT * FROM carte_autor WHERE id_carte = ?', id, (err, results) => {
                        if (err) { res.status(400).json('not found'); }
                        else {
                            let autor_id = results[0].id_autor;
                            db.query('SELECT * FROM autori WHERE id_autor = ?', autor_id, (err, results) => {
                                if (err) { res.status(400).json('not found'); }
                                else {
                                    autor = Object.values(JSON.parse(JSON.stringify(results)));
                                    //carte[0] = Object.assign( Object.values(JSON.parse(JSON.stringify(results))));
                                    rezultat = { ...carte[0], ...autor[0] };
                                    console.log(rezultat);
                                    db.query('SELECT * FROM carte_gen WHERE id_carte = ?', id, (err, results) => {
                                        if (err) { res.status(400).json('not found'); }
                                        else {
                                            console.log(results);
                                            results = Object.values(JSON.parse(JSON.stringify(results)));
                                            console.log(results);
                                            let idGenArray = [];
                                            for (i in results) {
                                                idGenArray.push(results[i].id_gen);
                                            }
                                            console.log(idGenArray);
                                            let genString = idGenArray.toString();
                                            console.log(genString);

                                            //idGenArray.forEach(id_gen => {
                                                db.query('SELECT * FROM genuri WHERE id_gen IN (?)', [idGenArray], (err, results) => {
                                                    if (err) { res.status(400).json('not found'); }
                                                    else {
                                                        console.log(results);
                                                        results = Object.values(JSON.parse(JSON.stringify(results)));
                                                        console.log(results);
                                                        //gen = Object.assign(gen, results);
                                                        for (i in results) {
                                                            gen.push(results[i].gen);
                                                        }
                                                        
                                                        console.log(gen);
                                                        rezultat.gen = Object.assign(gen);
                                                        console.log(rezultat);
                                                        db.query('SELECT * FROM reviews LEFT JOIN users ON reviews.id_user = users.id_user WHERE id_carte = ?', id, (err, results) => {
                                                            if (err) {
                                                                res.status(400).json('can\'t load');
                                                            }
                                                            else {
                                                                results = Object.values(JSON.parse(JSON.stringify(results)));
                                                                console.log("REview array:", results);
                                                                reviews = [...results];
                                                                console.log(reviews);
                                                                let array = [];
                                                                array.push(res.locals.user);
                                                                console.log(res.locals.user);
                                                                array.push(id);
                                                                console.log(id);
                                                                db.query('SELECT * FROM carti_users WHERE id_user = ? AND id_carte = ?', [res.locals.user, id], (err, results) => {
                                                                    if (err) {
                                                                        res.status(400).json('can\'t load');
                                                                    }
                                                                    else {
                                                                        results = Object.values(JSON.parse(JSON.stringify(results)));
                                                                        console.log("carti-users: ", results);
                                                                        if(results.length != 0) {
                                                                            if(results[0].id_eticheta === 1) {
                                                                                read.value = true;
                                                                            }
                                                                            if(results[0].id_eticheta === 2) {
                                                                                toRead.value = true;
                                                                            }
                                                                            if(results[0].id_eticheta === 3) {
                                                                                reading.value = true;
                                                                            }
                                                                        }
                                                                        console.log("read-",read, "toRead-", toRead, "Reading-", reading);
                                                                        res.render('carte.ejs', { carte: rezultat, reviews: reviews, toRead: toRead, read: read, reading: reading, username: username});
                                                                    }
                                                                })
                                                                
                                                            }
                                                        })
                                                        
                                                    }
                                                });
                                            //})
                                        }
                                    })
                                }
                            })
                        }
                    })
                }
            })
        }
    });
    
});

app.post('/search', (req, res) => {
    var str = {
        stringPart: req.body.typeahead
    }

    db.query('SELECT * FROM carti LEFT JOIN carte_autor ON carti.id_carte = carte_autor.id_carte LEFT JOIN autori ON autori.id_autor = carte_autor.id_autor WHERE titlu LIKE "%' 
    + str.stringPart + '%" OR isbn_carte LIKE "%' + str.stringPart + '%" OR nume_autor LIKE "%' + str.stringPart + '%"', (err, results) => {
        if (err) { throw err; }
        else {
            results = Object.values(JSON.parse(JSON.stringify(results)));
            console.log(results);

            res.render('rezultate.ejs', { rezultate: results });
        }
    });
});

app.post('/toRead', (req, res) => {
    let data = {
        id_user: res.locals.user,
        id_carte: req.body.id_carte,
        id_eticheta: 2
    }
    console.log(data);
    db.query('INSERT INTO carti_users SET ?', data, (err) => {
        if(err) {res.status(400).json('unable to add')}
        else {res.redirect('back')}
    });
})

app.post('/stergeToRead', (req, res) => {
    let data = {
        id_user: res.locals.user,
        id_carte: req.body.id_carte,
        id_eticheta: 2
    }
    console.log(data);
    db.query('DELETE FROM carti_users WHERE id_user = ? AND id_carte = ? AND id_eticheta = ?', [data.id_user, data.id_carte, data.id_eticheta], (err, result) => {
        if(err) {res.status(400).json('unable to delete')}
        else {res.redirect('back')}
    })
})

app.post('/read', (req, res) => {
    let data = {
        id_user: res.locals.user,
        id_carte: req.body.id_carte,
        id_eticheta: 1
    }
    console.log(data);
    db.query('INSERT INTO carti_users SET ?', data, (err) => {
        if(err) {res.status(400).json('unable to add')}
        else {res.redirect('back')}
    });
})

app.post('/stergeRead', (req, res) => {
    let data = {
        id_user: res.locals.user,
        id_carte: req.body.id_carte,
        id_eticheta: 1
    }
    console.log(data);
    db.query('DELETE FROM carti_users WHERE id_user = ? AND id_carte = ? AND id_eticheta = ?', [data.id_user, data.id_carte, data.id_eticheta], (err, result) => {
        if(err) {res.status(400).json('unable to delete')}
        else {res.redirect('back')}
    })
})

app.post('/reading', (req, res) => {
    let data = {
        id_user: res.locals.user,
        id_carte: req.body.id_carte,
        id_eticheta: 3
    }
    console.log(data);
    db.query('INSERT INTO carti_users SET ?', data, (err) => {
        if(err) {res.status(400).json('unable to add')}
        else {res.redirect('back')}
    });
})

app.post('/stergeReading', (req, res) => {
    let data = {
        id_user: res.locals.user,
        id_carte: req.body.id_carte,
        id_eticheta: 3
    }
    console.log(data);
    db.query('DELETE FROM carti_users WHERE id_user = ? AND id_carte = ? AND id_eticheta = ?', [data.id_user, data.id_carte, data.id_eticheta], (err, result) => {
        if(err) {res.status(400).json('unable to delete')}
        else {res.redirect('back')}
    })
})

app.post('/stergeCarte', (req, res) => {
    let data = {
        id_user: res.locals.user,
        id_carte: req.body.id_carte,
        id_eticheta: req.body.id_eticheta
    }
    console.log(data);
    db.query('DELETE FROM carti_users WHERE id_user = ? AND id_carte = ? AND id_eticheta = ?', [data.id_user, data.id_carte, data.id_eticheta], (err, result) => {
        if(err) {res.status(400).json('unable to delete')}
        else {res.redirect('back')}
    })
})

app.post('/review', (req, res) => {
    let data = {
        id_carte: req.body.id_carte,
        id_user: res.locals.user,
        review_body: req.body.review
    }
    console.log(data);
    db.query('INSERT INTO reviews SET ?', data, (err) => {
        if(err) {res.status(400).json('unable to add')}
        else {res.redirect('/carte/' + data.id_carte);}
    });
})

app.get('/admin', redirectLogin, redirectHome, (req, res) => {
    const { user, username } = res.locals
    let genuri = [];
    let carti = [];
    let autori = [];
    console.log("Home user: ", user);
    console.log(req.session);
    db.query('SELECT gen FROM genuri', (err, results) => {
        if (err) {
            res.status(400).json('can\'t load');
        }
        else {
            console.log("Genuri: ", results);
            results = Object.values(JSON.parse(JSON.stringify(results)))
            console.log("Genuri: ", results);
            genuri = results;
            console.log(genuri);
            db.query('SELECT * FROM carti LEFT JOIN carte_autor ON carti.id_carte = carte_autor.id_carte LEFT JOIN autori ON autori.id_autor = carte_autor.id_autor', (err, results) => {
                if(err) {
                    res.status(400).json('can\'t load');
                }
                else {
                    results = Object.values(JSON.parse(JSON.stringify(results)));
                    carti = results;
                    console.log(carti);
                    db.query('SELECT * FROM autori', (err, results) => {
                        if(err) {
                            res.status(400).json('can\'t load');
                        }
                        else {
                            results = Object.values(JSON.parse(JSON.stringify(results)));
                            autori = results;
                            console.log(autori);
                            res.render('admin.ejs', { genuri: genuri, id_user: user, username: username, carti: carti, autori: autori });
                        }
                    })
                }
            })
        }
    })
});

app.get('/genuri', redirectLogin, redirectAdmin, (req, res) => {
    const { username } = res.locals
    let genuri = [];
    let genId = []; 
    let carti = [];
    
    db.query('SELECT * FROM genuri', (err, results) => {
        if (err) {
            res.status(400).json('can\'t load');
        }
        else {
            results = Object.values(JSON.parse(JSON.stringify(results)));
            for(i in results) {
                genId.push(results[i].id_gen);
            }
            genuri = results;
            db.query('SELECT * FROM carte_gen WHERE id_gen IN (?)', [genId], (err, results) => {
                results = Object.values(JSON.parse(JSON.stringify(results)));
                for (i in genuri) {
                    genuri[i].id_carte = [];
                    for (j in results) {
                        if(results[j].id_gen === genuri[i].id_gen) {
                            genuri[i].id_carte.push(results[j].id_carte);
                        }
                    }
                }
                console.log(genuri);
                db.query('SELECT * FROM carti', (err, results) => {
                    results = Object.values(JSON.parse(JSON.stringify(results)));
                    //console.log(results);
                    //genuri.push({carti: results});
                    carti = results;
                    console.log(carti);
                    res.render('genuri.ejs', { genuri: genuri, carti: carti, username: username});
                })
            })

            
        }
    })
});

app.get('/gen/:id', redirectLogin, redirectAdmin, (req, res) => {
    let { id } = req.params;
    const { username } = res.locals;
    let gen = {};
    db.query('SELECT * FROM genuri  WHERE id_gen = ?', id, (err, results) => {
        if (err) {
            res.status(400).json('can\'t load');
        }
        else {
            console.log("Gen: ", results);
            results = Object.values(JSON.parse(JSON.stringify(results)));
            gen = { ...results[0] };
            console.log("Gen: ", gen);
            let idGen = results[0].id_gen;
            db.query('SELECT * FROM carte_gen WHERE id_gen = ?', idGen, (err, results) => {
                if (err) {
                    res.status(400).json('can\'t load');
                }
                else {
                    console.log("CArte_gen results: ", results);
                    results = Object.values(JSON.parse(JSON.stringify(results)));
                    let idCarte = [];
                    for (i in results) {
                        idCarte.push(results[i].id_carte);
                    }
                    console.log(idCarte);
                    //let idCarte = results[0].id_carte;
                    //console.log(idCarte);
                    gen.idCarte = idCarte;
                    console.log("Gen: ", gen);
                    db.query('SELECT * FROM carti WHERE id_carte IN (?)', [idCarte], (err, results) => {
                        if(err) {
                            res.status(400).json('can\'t load');
                        }
                        else {
                            console.log("Carti results: ", results);
                            results = Object.values(JSON.parse(JSON.stringify(results)));
                            gen.carti = results;
                            console.log("Gen final: ", gen);
                            res.render('gen.ejs', { gen: gen, username: username });
                        }
                    })
                }
            });
        }
    })

});

app.get('/cartileMele', redirectLogin, redirectAdmin, (req, res) => {
    const { user } = res.locals;
    let carti = [];
    db.query('SELECT * FROM carti_users LEFT JOIN carti ON carti.id_carte = carti_users.id_carte LEFT JOIN etichete ON carti_users.id_eticheta = etichete.id_eticheta LEFT JOIN carte_autor ON carte_autor.id_carte = carti_users.id_carte WHERE id_user = ?', user, (err, results) => {
        if(err) {
            res.json("Nu sunt cărți");
        } else {
        results = Object.values(JSON.parse(JSON.stringify(results)));
        console.log(results);
        carti = [...results];
        console.log(carti);
        let id_autor = [];
        carti.forEach(carte => {
            id_autor.push(carte.id_autor);
        });
        console.log(id_autor);
        db.query('SELECT * FROM autori WHERE id_autor IN (?)', [id_autor], (err, results) => {
            if(err) {
                res.status(400).redirect('/home', '<p>Nu sunt cărți</p>');
            } else {
            results = Object.values(JSON.parse(JSON.stringify(results)));
            console.log(results);
            for(let i = 0; i < id_autor.length; i++) {
                for(let j = 0; j < results.length; j++) {
                    if(id_autor[i] == results[j].id_autor) {
                        Object.assign(carti[i], { nume_autor: results[j].nume_autor });
                    }
                }
            }
            console.log(carti);
            res.render('cartilemele.ejs', { carti: carti });
            }
        });
        }
    });
});

app.post('/adaugareGen', (req, res) => {
    let data = {
        gen: req.body.gen
    }
    db.query('INSERT INTO genuri SET ?', data, (err) => {
        if (err) { res.status(400).json('unable to add') }
        else { res.redirect('back'); }
    })
});

app.post('/adaugareAutor', (req, res) => {
    let data = {
        nume_autor: req.body.nume_autor
    }
    db.query('INSERT INTO autori SET ?', data, (err) => {
        if (err) { res.status(400).json('unable to add') }
        else { res.redirect('back'); }
    })
});

app.post('/adaugareCarti', (req, res) => {
    upload(req, res, (err) => {
        if (err) {
            res.render('admin.ejs', {
                msg: err
            });
        } else {
            console.log(req.file);

            let data_carti = {
                isbn_carte: req.body.isbn,
                titlu: req.body.titlu,
                nr_pagini: req.body.nrPagini,
                descriere: req.body.descriere,
                coperta: req.file.filename
            }
            let autor = req.body.autor;
            let genArray = req.body.genCheckbox;

            db.beginTransaction((err) => {
                if (err) {
                    res.status(400).json('error');
                }
                else {
                    db.query('INSERT INTO carti SET ?', data_carti, (err, result) => {
                        if (err) { res.status(400).json('unable to add(carti)'); }
                        let id_carte = result.insertId;
                        db.query('SELECT id_autor FROM autori WHERE nume_autor = ?', autor, (err, result) => {
                            if (err) { res.status(400).json('err'); }

                            let autorId = result[0].id_autor;
                            let autor_carte = {
                                id_carte: id_carte,
                                id_autor: autorId
                            };
                            db.query('INSERT INTO carte_autor SET ?', autor_carte, (err) => {
                                if (err) { console.log(err); res.status(400).json('unable to add(carte_autor)'); }
                            });
                        });
                        genArray.forEach(gen => {
                            db.query('SELECT id_gen FROM genuri WHERE gen = ?', gen, (err, result) => {
                                if (err) {
                                    res.status(400).json('err');
                                }
                                let genId = result[0].id_gen;
                                let gen_carte = {
                                    id_carte: id_carte,
                                    id_gen: genId
                                };
                                db.query('INSERT INTO carte_gen SET ?', gen_carte, (err) => {
                                    if (err) { console.log(err); res.status(400).json('unable to add(carte_autor)'); }
                                });
                            })
                        });
                    });
                }
            });
            db.commit();
            res.redirect('/admin');
        }
    });
});


app.listen(3000, () => {
    console.log('app is running on port 3000');
})

