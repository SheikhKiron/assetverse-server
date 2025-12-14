import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { MongoClient, ObjectId } from 'mongodb';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import Stripe from 'stripe';

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// ===== Stripe =====

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// ===== MongoDB =====

const client = new MongoClient(process.env.MONGO_URI);
let db;
await client.connect();
db = client.db('assetverse');
console.log('MongoDB connected');

// collections

const usersCol = db.collection('users');
const assetsCol = db.collection('assets');
const packagesCol = db.collection('packages');
const requestsCol = db.collection('requests');

// ===== Seed default packages =====

const seedPackages = async () => {
  const count = await packagesCol.countDocuments();
  if (count === 0) {
    await packagesCol.insertMany([
      {
        name: 'Basic',
        employeeLimit: 5,
        price: 5,
        features: ['Asset Tracking', 'Employee Management', 'Basic Support'],
      },
      {
        name: 'Standard',
        employeeLimit: 10,
        price: 8,
        features: [
          'All Basic features',
          'Advanced Analytics',
          'Priority Support',
        ],
      },
      {
        name: 'Premium',
        employeeLimit: 20,
        price: 15,
        features: ['All Standard features', 'Custom Branding', '24/7 Support'],
      },
    ]);
    console.log('Default packages seeded');
  }
};

await seedPackages();

// ===== JWT Middleware =====

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send({ msg: 'No token provided' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; 
    next();
  } catch (err) {
    console.error('JWT Error:', err);
    res.status(403).send({ msg: 'Invalid token' });
  }
};

const verifyHR = (req, res, next) => {
  if (!req.user) return res.status(401).send({ msg: 'Unauthorized' });
  if (req.user.role !== 'hr') return res.status(403).send({ msg: 'HR only' });
  next();
};

const verifyEmployee = (req, res, next) => {
  if (!req.user) return res.status(401).send({ msg: 'Unauthorized' });
  if (req.user.role !== 'employee')
    return res.status(403).send({ msg: 'Employee only' });
  next();
};

// ==================== AUTH ====================

// HR Registration

app.post('/auth/register/hr', async (req, res) => {
  try {
    const { name, email, password, companyName, companyLogo, dateOfBirth } =
      req.body;
    if (!name || !email || !password || !companyName || !companyLogo)
      return res.status(400).send({ msg: 'All fields required' });

    const exist = await usersCol.findOne({ email });
    if (exist) return res.status(400).send({ msg: 'Email already exists' });

    const hashed = await bcrypt.hash(password, 10);

    const hr = {
      name,
      email,
      password: hashed,
      role: 'hr',
      companyName,
      companyLogo,
      dateOfBirth,
      subscription: 'basic',
      packageLimit: 5,
      currentEmployees: 0,
      approved: true,
      createdAt: new Date(),
    };

    const result = await usersCol.insertOne(hr);
    res.status(201).send({ msg: 'HR Registered', hrId: result.insertedId });
  } catch (err) {
    console.error('HR registration error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// Employee Registration

app.post('/auth/register/employee', async (req, res) => {
  try {
    const { name, email, password, dateOfBirth } = req.body;
    if (!name || !email || !password)
      return res.status(400).send({ msg: 'All fields required' });

    const exist = await usersCol.findOne({ email });
    if (exist) return res.status(400).send({ msg: 'Email already exists' });

    const hashed = await bcrypt.hash(password, 10);

    const employee = {
      name,
      email,
      password: hashed,
      role: 'employee',
      dateOfBirth,
      approved: false,
      createdAt: new Date(),
    };

    const result = await usersCol.insertOne(employee);
    res.status(201).send({
      msg: 'Employee Registered, waiting approval',
      employeeId: result.insertedId,
    });
  } catch (err) {
    console.error('Employee registration error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// Login (JWT)

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await usersCol.findOne({ email });
    if (!user) return res.status(400).send({ msg: 'User not found' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).send({ msg: 'Invalid password' });

    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.send({ token, user });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// ==================== HR: EMPLOYEES ====================


app.get('/hr/employees', async (req, res) => {
  try {
    const { hrEmail } = req.query;


    if (hrEmail) {
      const approvedReqs = await requestsCol
        .find({ hrEmail, requestStatus: 'approved' })
        .toArray();

      if (!approvedReqs.length) {
        return res.send([]); 
      }

      const emails = [...new Set(approvedReqs.map(r => r.requesterEmail))];

      const employees = await usersCol
        .find({
          email: { $in: emails },
          role: 'employee',
        })
        .toArray();

      return res.send(employees);
    }

 
    const employees = await usersCol
      .find({ role: 'employee', approved: true })
      .toArray();
    res.send(employees);
  } catch (err) {
    console.error(err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// Pending employees (JWT protected)

app.get('/hr/employees/pending', verifyToken, verifyHR, async (req, res) => {
  try {
    const employees = await usersCol
      .find({ role: 'employee', approved: false })
      .toArray();
    res.send(employees);
  } catch (err) {
    console.error(err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// Approve employee (JWT protected)
app.patch(
  '/hr/approve-employee/:id',
  verifyToken,
  verifyHR,
  async (req, res) => {
    try {
      const { id } = req.params;
      const result = await usersCol.updateOne(
        { _id: new ObjectId(id) },
        { $set: { approved: true } }
      );
      res.send({ msg: 'Employee Approved', result });
    } catch (err) {
      console.error(err);
      res.status(500).send({ msg: 'Server Error', error: err.toString() });
    }
  }
);

// ==================== HR: ASSETS ====================

// Add Asset
app.post('/hr/assets', async (req, res) => {
  try {
    const {
      productName,
      productImage,
      productType,
      productQuantity,
      hrEmail,
      companyName,
    } = req.body;

    if (!productName || !productImage || !productType || !productQuantity) {
      return res.status(400).send({ msg: 'All fields required' });
    }

    const qty = Number(productQuantity);

    const asset = {
      productName,
      productImage,
      productType, 
      productQuantity: qty,
      availableQuantity: qty,
      dateAdded: new Date(),
      hrEmail: hrEmail || null,
      companyName: companyName || '',
    };

    const result = await assetsCol.insertOne(asset);
    res.status(201).send({ msg: 'Asset created', id: result.insertedId });
  } catch (err) {
    console.error('Add asset error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// Get all assets
// app.get('/hr/assets', async (req, res) => {
//   try {
//     const assets = await assetsCol.find({}).toArray();
//     res.send(assets);
//   } catch (err) {
//     console.error('Get assets error:', err);
//     res.status(500).send({ msg: 'Server Error', error: err.toString() });
//   }
// });

// Get single asset by id

app.get('/hr/assets/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const asset = await assetsCol.findOne({ _id: new ObjectId(id) });
    if (!asset) return res.status(404).send({ msg: 'Asset not found' });
    res.send(asset);
  } catch (err) {
    console.error('Get single asset error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// Update asset
app.patch('/hr/assets/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { productName, productImage, productType, productQuantity } =
      req.body;

    const update = {};
    if (productName) update.productName = productName;
    if (productImage) update.productImage = productImage;
    if (productType) update.productType = productType;
    if (productQuantity !== undefined) {
      const qty = Number(productQuantity);
      update.productQuantity = qty;
      update.availableQuantity = qty;
    }

    const result = await assetsCol.updateOne(
      { _id: new ObjectId(id) },
      { $set: update }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ msg: 'Asset not found' });
    }

    res.send({ msg: 'Asset updated', result });
  } catch (err) {
    console.error('Update asset error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// Delete asset
app.delete('/hr/assets/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await assetsCol.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) {
      return res.status(404).send({ msg: 'Asset not found' });
    }
    res.send({ msg: 'Asset deleted' });
  } catch (err) {
    console.error('Delete asset error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// ==================== EMPLOYEE: REQUESTS ====================

// Create request
app.post('/employee/requests', async (req, res) => {
  try {
    const {
      assetId,
      assetName,
      assetType,
      companyName,
      hrEmail,
      requesterName,
      requesterEmail,
      note,
      assetImage,
    } = req.body;

    if (!assetId || !requesterEmail) {
      return res
        .status(400)
        .send({ msg: 'assetId and requesterEmail are required' });
    }

    const requestDoc = {
      assetId: new ObjectId(assetId),
      assetName,
      assetType,
      hrEmail: hrEmail || null,
      companyName: companyName || 'Unknown Company',
      requesterName,
      requesterEmail,
      assetImage: assetImage || null,
      requestDate: new Date(),
      approvalDate: null,
      requestStatus: 'pending',
      note: note || '',
      processedBy: null,
    };

    const result = await requestsCol.insertOne(requestDoc);

    res.status(201).send({
      msg: 'Request created',
      requestId: result.insertedId,
    });
  } catch (err) {
    console.error('Create request error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// My requests (for MyAssets)
app.get('/employee/requests/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const requests = await requestsCol
      .find({ requesterEmail: email })
      .sort({ requestDate: -1 })
      .toArray();
    res.send(requests);
  } catch (err) {
    console.error('My requests error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// Return asset
app.patch('/employee/requests/:id/return', async (req, res) => {
  try {
    const { id } = req.params;

    const request = await requestsCol.findOne({ _id: new ObjectId(id) });
    if (!request) return res.status(404).send({ msg: 'Request not found' });

    if (request.requestStatus !== 'approved') {
      return res
        .status(400)
        .send({ msg: 'Only approved requests can be returned' });
    }
    if (request.assetType !== 'Returnable') {
      return res
        .status(400)
        .send({ msg: 'Only returnable assets can be returned' });
    }

    await requestsCol.updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          requestStatus: 'returned',
          returnDate: new Date(),
        },
      }
    );

    if (request.assetId) {
      await assetsCol.updateOne(
        { _id: new ObjectId(request.assetId) },
        { $inc: { availableQuantity: 1 } }
      );
    }

    res.send({ msg: 'Asset returned' });
  } catch (err) {
    console.error('Return asset error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// ==================== EMPLOYEE: MY TEAM ====================

// My Team (company-wise colleagues)
app.get('/employee/my-team/:email', async (req, res) => {
  try {
    const { email } = req.params;

    const myApproved = await requestsCol
      .find({ requesterEmail: email, requestStatus: 'approved' })
      .toArray();

    if (myApproved.length === 0) {
      return res.send([]);
    }

    const companySet = new Set();
    myApproved.forEach(req => {
      const cName = req.companyName || 'Unknown Company';
      companySet.add(cName);
    });

    const teams = [];

    for (const companyName of companySet) {
      const companyReqs = await requestsCol
        .find({ companyName, requestStatus: 'approved' })
        .toArray();

      if (companyReqs.length === 0) continue;

      const emails = [...new Set(companyReqs.map(r => r.requesterEmail))];

      const colleagues = await usersCol
        .find({ email: { $in: emails } })
        .project({
          _id: 0,
          name: 1,
          email: 1,
          profileImage: 1,
          dateOfBirth: 1,
          position: 1,
        })
        .toArray();

      teams.push({
        companyName,
        colleagues,
      });
    }

    res.send(teams);
  } catch (err) {
    console.error('My team error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// ==================== HR: ALL REQUESTS ====================

// Get all requests
app.get('/hr/requests', async (req, res) => {
  try {
    const requests = await requestsCol
      .find({})
      .sort({ requestDate: -1 })
      .toArray();
    res.send(requests);
  } catch (err) {
    console.error('HR requests error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// Approve request
app.patch('/hr/requests/:id/approve', async (req, res) => {
  try {
    const { id } = req.params;

    const request = await requestsCol.findOne({
      _id: new ObjectId(id),
    });
    if (!request) return res.status(404).send({ msg: 'Request not found' });
    if (request.requestStatus !== 'pending') {
      return res.status(400).send({ msg: 'Request already processed' });
    }

    if (request.assetId) {
      await assetsCol.updateOne(
        { _id: new ObjectId(request.assetId) },
        { $inc: { availableQuantity: -1 } }
      );
    }

    const approvalDate = new Date();

    await requestsCol.updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          requestStatus: 'approved',
          approvalDate,
          processedBy: 'HR',
        },
      }
    );

    res.send({ msg: 'Request approved' });
  } catch (err) {
    console.error('Approve request error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// Reject request
app.patch('/hr/requests/:id/reject', async (req, res) => {
  try {
    const { id } = req.params;

    const request = await requestsCol.findOne({
      _id: new ObjectId(id),
    });
    if (!request) return res.status(404).send({ msg: 'Request not found' });
    if (request.requestStatus !== 'pending') {
      return res.status(400).send({ msg: 'Request already processed' });
    }

    await requestsCol.updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          requestStatus: 'rejected',
          approvalDate: new Date(),
          processedBy: 'HR',
        },
      }
    );

    res.send({ msg: 'Request rejected' });
  } catch (err) {
    console.error('Reject request error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// ==================== PACKAGES & STRIPE UPGRADE ====================


// Get all packages
app.get('/packages', async (req, res) => {
  try {
    const pkgs = await packagesCol.find({}).toArray();
    res.send(pkgs);
  } catch (err) {
    console.error('Packages error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// Create PaymentIntent
app.post('/create-payment-intent', async (req, res) => {
  try {
    const { packageName, hrEmail } = req.body;
    if (!packageName || !hrEmail) {
      return res
        .status(400)
        .send({ msg: 'packageName and hrEmail are required' });
    }

    const pkg = await packagesCol.findOne({ name: packageName });
    if (!pkg) return res.status(404).send({ msg: 'Package not found' });

    const amount = pkg.price * 100;

    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: 'usd',
      metadata: {
        packageName: pkg.name,
        hrEmail,
      },
    });

    res.send({
      clientSecret: paymentIntent.client_secret,
      package: {
        name: pkg.name,
        employeeLimit: pkg.employeeLimit,
        price: pkg.price,
      },
    });
  } catch (err) {
    console.error('Create payment intent error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// HR: Upgrade package
app.post('/hr/upgrade', async (req, res) => {
  try {
    const { hrEmail, packageName } = req.body;
    if (!hrEmail || !packageName) {
      return res.status(400).send({ msg: 'hrEmail and packageName required' });
    }

    const pkg = await packagesCol.findOne({ name: packageName });
    if (!pkg) return res.status(404).send({ msg: 'Package not found' });

    const result = await usersCol.updateOne(
      { email: hrEmail, role: 'hr' },
      {
        $set: {
          subscription: packageName.toLowerCase(),
          packageLimit: pkg.employeeLimit,
          updatedAt: new Date(),
        },
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ msg: 'HR user not found' });
    }

    res.send({
      msg: 'Package upgraded',
      packageName: pkg.name,
      employeeLimit: pkg.employeeLimit,
      price: pkg.price,
    });
  } catch (err) {
    console.error('Upgrade package error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});

// ==================== USERS / PROFILE ====================

// Get user by email
app.get('/users/by-email/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const user = await usersCol.findOne({ email });
    if (!user) return res.status(404).send({ msg: 'User not found' });

    let employees = [];
    if (user.role === 'hr') {
      employees = await usersCol
        .find({ role: 'employee', approved: true })
        .toArray();
    }

    res.send({ user, employees });
  } catch (err) {
    console.error(err);
    res.status(500).send({ msg: 'Server error', error: err.toString() });
  }
});


app.get(
  '/employee/my-profile',
  verifyToken,
  verifyEmployee,
  async (req, res) => {
    try {
      const employee = await usersCol.findOne({ email: req.user.email });
      res.send(employee);
    } catch (err) {
      console.error(err);
      res.status(500).send({ msg: 'Server Error', error: err.toString() });
    }
  }
);

app.get('/hr/analytics/asset-types', async (req, res) => {
  try {
    const { hrEmail } = req.query;

    const matchStage = {};
    if (hrEmail) matchStage.hrEmail = hrEmail;

    const agg = await assetsCol
      .aggregate([
        { $match: matchStage },
        {
          $group: {
            _id: '$productType',
            count: { $sum: 1 },
          },
        },
      ])
      .toArray();

    let returnable = 0;
    let nonReturnable = 0;

    agg.forEach(item => {
      if (item._id === 'Returnable') returnable = item.count;
      else if (item._id === 'Non-returnable') nonReturnable = item.count;
    });

    const data = [
      { name: 'Returnable', value: returnable },
      { name: 'Non-returnable', value: nonReturnable },
    ];

    res.send(data);
  } catch (err) {
    console.error('Asset types analytics error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});


app.get('/hr/analytics/top-requested', async (req, res) => {
  try {
    const { hrEmail } = req.query;

    const matchStage = {};
    if (hrEmail) matchStage.hrEmail = hrEmail;

    const agg = await requestsCol
      .aggregate([
        { $match: matchStage },
        {
          $group: {
            _id: '$assetName',
            count: { $sum: 1 },
          },
        },
        { $sort: { count: -1 } },
        { $limit: 5 },
      ])
      .toArray();

    const data = agg.map(item => ({
      assetName: item._id,
      count: item.count,
    }));

    res.send(data);
  } catch (err) {
    console.error('Top requested analytics error:', err);
    res.status(500).send({ msg: 'Server Error', error: err.toString() });
  }
});
// pagination
// app.get('/hr/assets', async (req, res) => {
//   try {
//     const { page = 1, limit = 10, hrEmail } = req.query;

//     const pageNum = Number(page) || 1;
//     const limitNum = Number(limit) || 10;
//     const skip = (pageNum - 1) * limitNum;

//     const query = {};
//     if (hrEmail) query.hrEmail = hrEmail;
//     const total = await assetsCol.countDocuments(query);

//     const assets = await assetsCol
//       .find(query)
//       .sort({ dateAdded: -1 })
//       .skip(skip)
//       .limit(limitNum)
//       .toArray();

//     res.send({
//       data: assets,
//       total,
//       page: pageNum,
//       limit: limitNum,
//       totalPages: Math.ceil(total / limitNum) || 1,
//     });
//   } catch (err) {
//     console.error('Get assets error:', err);
//     res.status(500).send({ msg: 'Server Error', error: err.toString() });
//   }
// });


app.get('/hr/assets', async (req, res) => {
  try {
    const { page = 1, limit = 10, hrEmail } = req.query;

    const pageNum = Number(page);
    const limitNum = Number(limit);
    const skip = (pageNum - 1) * limitNum;

    const query = {};
    if (hrEmail) query.hrEmail = hrEmail;

    const total = await assetsCol.countDocuments(query);

    const assets = await assetsCol
      .find(query)
      .sort({ dateAdded: -1 })
      .skip(skip)
      .limit(limitNum)
      .toArray();

    res.send({
      data: assets,
      total,
      page: pageNum,
      limit: limitNum,
      totalPages: Math.ceil(total / limitNum),
    });
  } catch (err) {
    console.error(err);
    res.status(500).send({ msg: 'Server Error' });
  }
});


// ==================== TEST ====================
app.get('/', (req, res) => res.send('AssetVerse API Running'));

// ==================== START SERVER ====================
app.listen(process.env.PORT || 5000, () =>
  console.log('Server running on port ' + (process.env.PORT || 5000))
);
