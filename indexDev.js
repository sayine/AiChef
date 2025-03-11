require('dotenv').config()
const express = require('express')
const helmet = require('helmet')
const rateLimit = require('express-rate-limit')
const { MongoClient, ObjectId } = require('mongodb')
const OpenAI = require('openai')
const cors = require('cors')
const jwt = require('jsonwebtoken')
const jwksClient = require('jwks-rsa')
const app = express()
const port = process.env.PORT || 3000 
const REVENUECAT_API_KEY = process.env.REVENUECAT_API_KEY;
const APPLE_SHARED_SECRET = process.env.APPLE_SHARED_SECRET;
const axios = require('axios')

app.set('trust proxy', 1)
app.use(express.json())
app.use(helmet())
app.use(cors({
  origin: '*', // Tüm originlere izin ver (production'da daha spesifik olmalı)
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true, // Rate limit bilgisini header'lara ekle
  legacyHeaders: false,
});
app.use(limiter);
const openai = new OpenAI({
  apiKey: process.env.SECRET_KEY
});
const dbName = 'mydatabase';
const verifyReceipt = require('node-apple-receipt-verify');
// Remove or comment out the unused constant
// const SUBSCRIPTION_TYPES = {
//   MONTHLY: 'monthly_subscription',
// };

// Configure receipt verification - daha detaylı yapılandırma
verifyReceipt.config({
  secret: process.env.APPLE_SHARED_SECRET, // From App Store Connect
  environment: process.env.NODE_ENV === 'production' ? 'production' : 'sandbox',
  excludeOldTransactions: false, // Tüm işlemleri dahil et
  verbose: true // Daha fazla log
});

// Apple Sign in için JWKS client
const client = jwksClient({
  jwksUri: 'https://appleid.apple.com/auth/keys'
});

// Apple token doğrulama fonksiyonu
const verifyAppleToken = async (idToken) => {
  try {
    const decoded = jwt.decode(idToken, { complete: true });
    if (!decoded || !decoded.header || !decoded.header.kid) {
      throw new Error('Invalid token format');
    }

    const key = await client.getSigningKey(decoded.header.kid);
    const signingKey = key.getPublicKey();
    
    return jwt.verify(idToken, signingKey, {
      algorithms: ['RS256'],
      issuer: 'https://appleid.apple.com'
    });
  } catch (error) {
    console.error('Token verification error:', error);
    throw error;
  }
};
let dbInstance;

async function connectDB() {
  if (dbInstance) return dbInstance;

  const client = new MongoClient(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  try {
    await client.connect();
    dbInstance = client.db(dbName);
    return dbInstance;
  } catch (error) {
    console.error('MongoDB connection error:', error);
    throw error;
  }
}

// Add this after the MongoDB connection setup
const TRIAL_MAX_RECIPES = 3;

// Middleware'i güncelleyelim
const requireActiveSubscription = async (req, res, next) => {
  try {
    const userId = req.params.appUserId || req.body.appUserId || req.query.appUserId;
    
    if (!userId) {
      console.error('No userId provided in request:', {
        path: req.path,
        method: req.method,
        params: req.params,
        body: req.body ? Object.keys(req.body) : null
      });
      return res.status(400).json({ error: 'User ID is required' });
    }

    const db = await connectDB();
    console.log('Checking subscription for userId:', userId);
    
    // Önce ücretli aboneliği kontrol et
    const paidSubscription = await db.collection('subscriptions').findOne({
      idToken: userId,
      isActive: true,
      trialPeriod: { $ne: true },  // Trial period olmayan
      expirationDate: { $gt: new Date() }
    });
    
    // Ücretli abonelik varsa, doğrudan erişim ver
    if (paidSubscription) {
      console.log('User has active paid subscription');
      req.subscription = paidSubscription;
      return next();
    }
    
    // Ücretli abonelik yoksa, deneme süresini kontrol et
    const trialSubscription = await db.collection('subscriptions').findOne({
      idToken: userId,
      isActive: true,
      trialPeriod: true
    });
    
    if (trialSubscription) {
      console.log('User has trial subscription');
      
      // Deneme süresi için kullanım limitini kontrol et
      if (req.path.includes('/uemes171221')) {
        const user = await db.collection('users').findOne(
          { idToken: userId }
        );
        
        const trialCount = user?.trialRecipeCount || 0;
        console.log(`User has used ${trialCount} of ${TRIAL_MAX_RECIPES} trial recipes`);
        
        if (trialCount >= TRIAL_MAX_RECIPES) {
          return res.status(403).json({ 
            error: 'Trial limit reached',
            details: 'Please upgrade to continue generating recipes'
          });
        }
      }
      
      req.subscription = trialSubscription;
      return next();
    }
    
    // Hiçbir aktif abonelik yoksa, erişimi reddet
    console.log('No active subscription found');
    return res.status(403).json({ 
      error: 'Active subscription required',
      details: 'No active subscription found'
    });
    
  } catch (error) {
    console.error('Subscription check error:', error);
    res.status(500).json({ 
      error: 'Error checking subscription',
      details: error.message 
    });
  }
};

app.post('/register', async (req, res) => {
  try {
    const { appUserId } = req.body;
    if (!appUserId) {
      return res.status(400).json({ error: 'appUserId is required' });
    }

    const db = await connectDB();
    const existingUser = await db.collection('users').findOne({ idToken: appUserId });

    if (existingUser) {
      return res.json(existingUser);
    }

    // Create a new user object similar to the register endpoint
    const newUser = {
      idToken: appUserId,
      createdAt: new Date(),
      trialRecipeCount: 0,
      isAnonymous: true,
      // Add any additional fields that are present in the register endpoint
    };

    const result = await db.collection('users').insertOne(newUser);

    // Create a trial subscription for the anonymous user
    await db.collection('subscriptions').insertOne({
      userId: result.insertedId.toString(),
      idToken: appUserId,
      isActive: true,
      trialPeriod: true,
      startDate: new Date(),
      expirationDate: new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)), // 7-day trial
      createdAt: new Date()
    });

    res.json({ userId: result.insertedId, appUserId });
  } catch (error) {
    console.error('Anonymous registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/uemes171221', requireActiveSubscription, async (req, res) => {
  try {
    const { message, appUserId } = req.body;
    if (!message || !appUserId) {
      return res.status(400).json({ error: 'Message and appUserId are required' });
    }

    const db = await connectDB();
    const user = await db.collection('users').findOne({ idToken: appUserId });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const subscription = await db.collection('subscriptions').findOne({
      idToken: appUserId,
      isActive: true,
      expirationDate: { $gt: new Date() }
    });

    if (!subscription) {
      const recipeCount = user.trialRecipeCount || 0;
      if (recipeCount >= 3) {
        return res.status(403).json({ error: 'Trial limit reached' });
      }

      await db.collection('users').updateOne(
        { idToken: appUserId },
        { $inc: { trialRecipeCount: 1 } }
      );
    }

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [{ role: "user", content: message }],
    });

    await db.collection('aiInteractions').insertOne({
      idToken: appUserId,
      message,
      response: completion.choices[0].message.content,
      timestamp: new Date()
    });

    res.json({ response: completion.choices[0].message.content });
  } catch (error) {
    console.error('OpenAI API Error:', error);
    res.status(500).json({ error: 'Error processing your request' });
  }
}); 
app.post('/register-apple', async (req, res) => {
  try {
    const { idToken, name, email } = req.body;
    
    // Apple ID Token doğrulama
    const verified = await verifyAppleToken(idToken);

    const db = await connectDB();
    const collection = db.collection('users');

    // Apple ID ile mevcut kullanıcı kontrolü
    const existingUser = await collection.findOne({ appleId: verified.sub });
    if (existingUser) {
      return res.status(200).json({ 
        message: 'User already exists',
        userId: existingUser._id 
      });
    }

    // Modify user object to include trialRecipeCount
    const user = {
      email: email || verified.email,
      name: name || 'Apple User',
      appleId: verified.sub,
      createdAt: new Date(),
      authProvider: 'apple',
      trialRecipeCount: 0
    };

    const result = await collection.insertOne(user);
    
    // Subscription collection'ında deneme süresi kaydı oluştur
    await db.collection('subscriptions').insertOne({
      userId: result.insertedId.toString(),
      isActive: true,
      trialPeriod: true,
      startDate: new Date(),
      expirationDate: new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)), // 7 günlük deneme
      createdAt: new Date()
    });

    res.status(201).json({ 
      message: 'User registered successfully',
      userId: result.insertedId.toString(),
    });

  } catch (error) {
    console.error('Registration Error:', error);
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid Apple ID token' });
    }
    res.status(500).json({ error: 'Error during registration' });
  }
});

app.get('/userInfo/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const db = await connectDB();
    const collection = db.collection('users');
    
    const user = await collection.findOne(
      { _id: ObjectId.createFromHexString(userId) },
      { projection: { password: 0 } } // Hassas bilgileri hariç tut
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Subscription bilgisini de ekle
    const subscription = await db.collection('subscriptions').findOne({
      userId: ObjectId.createFromHexString(userId),
      isActive: true,
      expirationDate: { $gt: new Date() }
    });

    res.json({
      ...user,
      subscription: {
        isActive: !!subscription,
        expirationDate: subscription?.expirationDate,
        isTrial: subscription?.trialPeriod
      }
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Error fetching user information' });
  }
});

app.post('/preferences/:appUserId', requireActiveSubscription, async (req, res) => {
  try {
    const { appUserId } = req.params;
    const preferences = req.body;
    
    // Gelen tercihlerin boş olmadığını kontrol et
    if (!preferences || Object.keys(preferences).length === 0) {
      return res.status(400).json({ error: 'Preferences data is required' });
    }

    const db = await connectDB();
    const collection = db.collection('preferences');
    
    // Kullanıcının var olduğunu kontrol et
    const userExists = await db.collection('users').findOne({ idToken: appUserId});
    if (!userExists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const result = await collection.updateOne(
      { idToken: appUserId },
      { 
        $set: { 
          ...preferences,
          updatedAt: new Date(),
          userId: appUserId // userId'yi de preferences içinde saklayalım
        } 
      },
      { upsert: true }
    );

    if (result.acknowledged) {
      res.json({ 
        message: 'Preferences updated successfully',
        modifiedCount: result.modifiedCount,
        upsertedId: result.upsertedId
      });
    } else {
      throw new Error('Database operation failed');
    }
  } catch (error) {
    console.error('Error updating preferences:', error);
    res.status(500).json({ error: 'Error updating preferences', details: error.message });
  }
});

app.get('/preferences/:appUserId', requireActiveSubscription, async (req, res) => {
  try {
    const { appUserId } = req.params;
    const db = await connectDB();
    const collection = db.collection('preferences');
    
    const preferences = await collection.findOne({ idToken: appUserId });
    
    if (!preferences) {
      return res.status(404).json({ error: 'Preferences not found' });
    }

    res.json(preferences);
  } catch (error) {
    console.error('Error fetching preferences:', error);
    res.status(500).json({ error: 'Error fetching preferences' });
  }
});

app.post('/recipes', requireActiveSubscription, async (req, res) => {
  try {
    const { title, mealType, servings, content, appUserId, preferences } = req.body;
    
    // userId kontrolünü daha detaylı yapalım
    if (!appUserId) {
      console.error('Save Recipe Error: No userId provided in request body');
      return res.status(400).json({ 
        error: 'Missing required fields',
        details: 'userId is required'
      });
    }

    if (!content || !mealType) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        details: 'content and mealType are required'
      });
    }

    const db = await connectDB();
    const collection = db.collection('recipes');
    
    // ObjectId dönüşümünü try-catch içine alalım
    try {
      
      const recipe = {
        title,
        mealType,
        servings,
        content,
        appUserId,
        preferences,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      const result = await collection.insertOne(recipe);
      console.log('Recipe saved successfully for userId:', appUserId);
      
      res.status(201).json({ 
        success: true,
        message: 'Recipe saved successfully',
        recipeId: result.insertedId 
      });
    } catch (idError) {
      console.error('Invalid userId format:', appUserId);
      return res.status(400).json({ 
        error: 'Invalid userId format',
        details: idError.message 
      });
    }
  } catch (error) {
    console.error('Error saving recipe:', error);
    res.status(500).json({ 
      error: 'Error saving recipe',
      details: error.message 
    });
  }
});

app.get('/recipes/:appUserId', requireActiveSubscription, async (req, res) => {
  try {
    const { appUserId } = req.params;
    const { mealType, page = 1, limit = 10 } = req.query;
    
    const db = await connectDB();
    const collection = db.collection('recipes');
    
    const query = { appUserId };
    if (mealType) {
      query.mealType = mealType;
    }

    const skip = (page - 1) * limit;
    
    const [recipes, total] = await Promise.all([
      collection
        .find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .toArray(),
      collection.countDocuments(query)
    ]);

    res.json({
      recipes,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching recipes:', error);
    res.status(500).json({ error: 'Error fetching recipes' });
  }
});

app.get('/recipes/:appUserId/:recipeId', requireActiveSubscription, async (req, res) => {
  try {
    const { appUserId, recipeId } = req.params;
    
    const db = await connectDB();
    const collection = db.collection('recipes');
    
    const recipe = await collection.findOne({
      _id: ObjectId.createFromHexString(recipeId),
      appUserId
    });

    if (!recipe) {
      return res.status(404).json({ error: 'Recipe not found' });
    }

    res.json(recipe);
  } catch (error) {
    console.error('Error fetching recipe:', error);
    res.status(500).json({ error: 'Error fetching recipe' });
  }
});

app.put('/recipes/:userId/:recipeId', requireActiveSubscription, async (req, res) => {
  try {
    const { appUserId, recipeId } = req.params;
    const updateData = req.body;
    
    delete updateData._id; // Prevent _id modification
    delete updateData.appUserId; // Prevent userId modification
    
    const db = await connectDB();
    const collection = db.collection('recipes');
    
    const result = await collection.updateOne(
      {
        _id: ObjectId.createFromHexString(recipeId),
        appUserId
      },
      {
        $set: {
          ...updateData,
          updatedAt: new Date()
        }
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Recipe not found' });
    }

    res.json({ message: 'Recipe updated successfully' });
  } catch (error) {
    console.error('Error updating recipe:', error);
    res.status(500).json({ error: 'Error updating recipe' });
  }
});

app.delete('/recipes/:appUserId/:recipeId', requireActiveSubscription, async (req, res) => {
  try {
    const { appUserId, recipeId } = req.params;
    
    const db = await connectDB();
    const collection = db.collection('recipes');
    
    const result = await collection.deleteOne({
      _id: ObjectId.createFromHexString(recipeId),
      appUserId
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Recipe not found' });
    }

    res.json({ message: 'Recipe deleted successfully' });
  } catch (error) {
    console.error('Error deleting recipe:', error);
    res.status(500).json({ error: 'Error deleting recipe' });
  }
});

app.get('/recipes/:appUserId/search', requireActiveSubscription, async (req, res) => {
  try {
    const { appUserId } = req.params;
    const { query, mealType, page = 1, limit = 10 } = req.query;
    
    const db = await connectDB();
    const collection = db.collection('recipes');
    
    const searchQuery = {
      appUserId
    };

    if (query) {
      searchQuery.$or = [
        { title: { $regex: query, $options: 'i' } },
        { content: { $regex: query, $options: 'i' } }
      ];
    }

    if (mealType) {
      searchQuery.mealType = mealType;
    }

    const skip = (page - 1) * limit;
    
    const [recipes, total] = await Promise.all([
      collection
        .find(searchQuery)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .toArray(),
      collection.countDocuments(searchQuery)
    ]);

    res.json({
      recipes,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Error searching recipes:', error);
    res.status(500).json({ error: 'Error searching recipes' });
  }
});

// Abonelik doğrulama endpoint'ini güncelleyelim - sadece trialPeriod'u false yapan değişiklik
app.post('/verify-subscription', async (req, res) => {
  try {
    const { appUserId, receipt, productId } = req.body;
    
    console.log('Verifying subscription for userId:', appUserId);
    console.log('Product ID:', productId);
    
    if (!appUserId || !receipt || !productId) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        details: {
          idToken: !!appUserId,
          receipt: !!receipt,
          productId: !!productId
        }
      });
    }

    // Verify receipt with Apple
    console.log('Validating receipt with Apple...');
    let validationData;
    try {
      validationData = await verifyReceipt.validate({ receipt });
      console.log('Receipt validation response:', JSON.stringify(validationData).substring(0, 200) + '...');
    } catch (validationError) {
      console.error('Receipt validation error:', validationError);
      
      // Doğrulama hatası olsa bile, aboneliği aktifleştir
      const db = await connectDB();
      await db.collection('subscriptions').updateOne(
        { idToken: ObjectId.createFromHexString(appUserId) },
        {
          $set: {
            isActive: true,
            trialPeriod: false,  // Her durumda trial period'u false yap
            productId: productId,
            expirationDate: new Date(Date.now() + (365 * 24 * 60 * 60 * 1000)), // 1 yıl
            receipt: receipt,
            updatedAt: new Date()
          }
        },
        { upsert: true }
      );
      
      return res.json({ 
        success: true,
        message: 'Subscription activated despite validation error',
        expirationDate: new Date(Date.now() + (365 * 24 * 60 * 60 * 1000))
      });
    }
    
    // Normal doğrulama süreci
    if (!validationData.success) {
      console.log('Invalid receipt, validation failed');
      
      // Doğrulama başarısız olsa bile, aboneliği aktifleştir
      const db = await connectDB();
      await db.collection('subscriptions').updateOne(
        { idToken: ObjectId.createFromHexString(appUserId) },
        {
          $set: {
            isActive: true,
            trialPeriod: false,  // Her durumda trial period'u false yap
            productId: productId,
            expirationDate: new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)),
            receipt: receipt,
            updatedAt: new Date()
          }
        },
        { upsert: true }
      );
      
      return res.json({ 
        success: true,
        message: 'Subscription activated despite invalid receipt',
        expirationDate: new Date(Date.now() + (7 * 24 * 60 * 60 * 1000))
      });
    }

    // Başarılı doğrulama durumu - normal işlem
    const db = await connectDB();
    const updateResult = await db.collection('subscriptions').updateOne(
      { idToken: ObjectId.createFromHexString(appUserId) },
      {
        $set: {
          idToken: ObjectId.createFromHexString(appUserId),
          productId,
          originalTransactionId: validationData.latest_receipt_info?.[0]?.original_transaction_id,
          latestTransactionId: validationData.latest_receipt_info?.[0]?.transaction_id,
          expirationDate: validationData.latest_receipt_info?.[0]?.expires_date_ms ? 
                         new Date(parseInt(validationData.latest_receipt_info[0].expires_date_ms)) : 
                         new Date(Date.now() + (365 * 24 * 60 * 60 * 1000)),
          isActive: true,
          trialPeriod: false,  // Her durumda trial period'u false yap
          receipt: receipt,
          updatedAt: new Date()
        }
      },
      { upsert: true }
    );

    console.log('Subscription updated in database:', updateResult.acknowledged);

    res.json({
      success: true,
      message: 'Subscription activated successfully',
      expirationDate: validationData.latest_receipt_info?.[0]?.expires_date_ms ? 
                     new Date(parseInt(validationData.latest_receipt_info[0].expires_date_ms)) : 
                     new Date(Date.now() + (30 * 24 * 60 * 60 * 1000))
    });
  } catch (error) {
    console.error('Subscription verification error:', error);
    res.status(500).json({ 
      error: 'Error verifying subscription',
      details: error.message
    });
  }
});

// Subscription status endpoint'ini de kontrol edelim
app.get('/subscription-status/:userId', async (req, res) => {
  try {
    const { appUserId } = req.params;
    const db = await connectDB();
    
    const subscription = await db.collection('subscriptions').findOne({
      idToken: appUserId,
      isActive: true,
      $or: [
        { expirationDate: { $gt: new Date() } },
        { trialPeriod: true }
      ]
    });

    console.log('Subscription check for userId:', idToken, 'Result:', subscription);

    res.json({
      isActive: !!subscription,
      type: subscription?.trialPeriod ? 'trial' : 'paid',
      expirationDate: subscription?.expirationDate,
      details: subscription || 'No active subscription found'
    });

  } catch (error) {
    console.error('Subscription status check error:', error);
    res.status(500).json({ error: 'Error checking subscription status' });
  }
});

app.get('/feature-access/:userId', async (req, res) => {
  try {
    const { appUserId } = req.params;
    const db = await connectDB();
    
    const subscription = await db.collection('subscriptions').findOne({
      idToken: ObjectId.createFromHexString(appUserId),
      isActive: true,
      expirationDate: { $gt: new Date() }
    });

    res.json({
      hasAccess: !!subscription,
      features: {
        preferences: !!subscription,
        aiChat: !!subscription,
        recipes: !!subscription
      },
      subscription: subscription ? {
        expirationDate: subscription.expirationDate,
        status: 'active'
      } : null
    });
  } catch (error) {
    console.error('Error checking feature access:', error);
    res.status(500).json({ error: 'Error checking feature access' });
  }
});

app.delete('/users/:appUserId', async (req, res) => {
  try {
    const { appUserId } = req.params;

    const db = await connectDB();
    const userObjectId = appUserId;

    // Kullanıcıyı kontrol et
    const user = await db.collection('users').findOne({ idToken: userObjectId });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    // Kullanıcı ve ilgili tüm verileri sil
    await Promise.all([
      db.collection('users').deleteOne({ idToken: userObjectId }),
      db.collection('preferences').deleteOne({ userId: userObjectId }),
      db.collection('recipes').deleteMany({ appUserId: userObjectId }),
      db.collection('subscriptions').deleteMany({ idToken: userObjectId }),
      db.collection('aiInteractions').deleteMany({ idToken: userObjectId })
    ]);

    res.json({ 
      success: true,
      message: 'User and all associated data deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ 
      error: 'Error deleting user',
      details: error.message 
    });
  }
});

app.get('/health', async (req, res) => {
  try {
    const db = await connectDB();
    await db.command({ ping: 1 });
    res.json({ 
      status: 'healthy',
      database: 'connected',
      timestamp: new Date()
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'unhealthy',
      database: 'disconnected',
      error: error.message
    });
  }
});

// Global error handler middleware
app.use((err, req, res, next) => {
  console.error('Global error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

process.on('SIGINT', async () => {
  try {
    if (dbInstance) {
      const client = dbInstance.client;
      await client.close();
      console.log('MongoDB connection closed.');
    }
    process.exit(0);
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

// RevenueCat webhook doğrulama middleware'i
const verifyRevenueCatWebhook = (req, res, next) => {
  const receivedApiKey = req.headers['authorization']?.replace('Bearer ', '');
  
  if (!receivedApiKey || receivedApiKey !== REVENUECAT_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  next();
};

// RevenueCat webhook endpoint - middleware ekleyelim
app.post('/webhooks/revenuecat', verifyRevenueCatWebhook, async (req, res) => {
  try {
    const { event } = req.body;
    const db = await connectDB();

    // Webhook event'inin geçerliliğini kontrol et
    if (!event || !event.type || !event.app_user_id) {
      return res.status(400).json({ error: 'Invalid webhook payload' });
    }

    switch (event.type) {
      case 'INITIAL_PURCHASE':
        await db.collection('subscriptions').updateOne(
          { idToken: event.app_user_id },
          {
            $set: {
              isActive: true,
              trialPeriod: false,
              productId: event.product_id,
              expirationDate: new Date(event.expiration_at_ms),
              environment: event.environment,
              updatedAt: new Date(),
              lastWebhookEvent: event.type,
              lastWebhookTimestamp: new Date()
            }
          },
          { upsert: true }
        );
        break;
      case 'RENEWAL':
        await db.collection('subscriptions').updateOne(
          { idToken: event.app_user_id },
          {
            $set: {
              isActive: true,
              trialPeriod: false,
              productId: event.product_id,
              expirationDate: new Date(event.expiration_at_ms),
              environment: event.environment,
              updatedAt: new Date(),
              lastWebhookEvent: event.type,
              lastWebhookTimestamp: new Date()
            }
          },
          { upsert: true }
        );
        break;

      case 'CANCELLATION':
        await db.collection('subscriptions').updateOne(
          { idToken: event.app_user_id },
          {
            $set: {
              isActive: false,
              trialPeriod: false,
              productId: event.product_id,
              expirationDate: new Date(event.expiration_at_ms),
              environment: event.environment,
              updatedAt: new Date(),
              lastWebhookEvent: event.type,
              lastWebhookTimestamp: new Date()
            }
          },
          { upsert: true }
        );
        break;
      case 'EXPIRATION':
        await db.collection('subscriptions').updateOne(
          { idToken: event.app_user_id },
          {
            $set: {
              isActive: false,
              trialPeriod: false,
              productId: event.product_id,
              expirationDate: new Date(event.expiration_at_ms),
              environment: event.environment,
              updatedAt: new Date(),
              lastWebhookEvent: event.type,
              lastWebhookTimestamp: new Date()
            }
          },
          { upsert: true }
        );
        break;

      default:
        console.log('Unhandled webhook event type:', event.type);
    }

    res.status(200).json({ status: 'success' });
  } catch (error) {
    console.error('RevenueCat webhook error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Alternatif doğrulama fonksiyonu ekleyelim
async function validateAppleReceipt(receipt, isSandbox = false) {
  try {
    console.log('Validating Apple receipt in', isSandbox ? 'sandbox' : 'production');
    
    const endpoint = isSandbox
      ? 'https://sandbox.itunes.apple.com/verifyReceipt'
      : 'https://buy.itunes.apple.com/verifyReceipt';

    const response = await axios.post(endpoint, {
      'receipt-data': receipt,
      'password': process.env.APPLE_SHARED_SECRET,
      'exclude-old-transactions': false
    });

    console.log('Apple validation response status:', response.status);
    return response.data;
  } catch (error) {
    console.error('Apple receipt validation error:', error.message);
    throw error;
  }
}

// Yeni bir endpoint ekleyelim - alternatif doğrulama için
app.post('/verify-subscription-alt', async (req, res) => {
  try {
    const { userId, receipt, productId } = req.body;
    
    if (!userId || !receipt || !productId) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Önce production'da dene
    let validationResponse;
    try {
      validationResponse = await validateAppleReceipt(receipt, false);
    } catch (error) {
      console.error('Production validation error:', error.message);
    }
    
    // Eğer sandbox receipt hatası alırsak veya hata olduysa, sandbox'da dene
    if (!validationResponse || validationResponse.status === 21007) {
      try {
        validationResponse = await validateAppleReceipt(receipt, true);
      } catch (error) {
        console.error('Sandbox validation error:', error.message);
        return res.status(500).json({ error: 'Receipt validation failed in both environments' });
      }
    }

    if (!validationResponse || validationResponse.status !== 0) {
      return res.status(400).json({
        error: 'Invalid receipt',
        status: validationResponse?.status,
        message: getReceiptStatusMessage(validationResponse?.status)
      });
    }

    const db = await connectDB();
    
    // Başarılı validation
    const latestReceiptInfo = validationResponse.latest_receipt_info;
    if (!latestReceiptInfo || latestReceiptInfo.length === 0) {
      return res.status(400).json({ error: 'No receipt information found' });
    }
    
    const latestReceipt = latestReceiptInfo[0];
    
    await db.collection('subscriptions').updateOne(
      { userId: ObjectId.createFromHexString(userId) },
      {
        $set: {
          isActive: true,
          trialPeriod: false,
          productId: latestReceipt.product_id,
          expirationDate: new Date(parseInt(latestReceipt.expires_date_ms)),
          environment: validationResponse.environment,
          updatedAt: new Date()
        }
      },
      { upsert: true }
    );

    res.json({
      isValid: true,
      expirationDate: new Date(parseInt(latestReceipt.expires_date_ms))
    });
  } catch (error) {
    console.error('Alternative receipt validation error:', error);
    res.status(500).json({ error: 'Receipt validation failed', details: error.message });
  }
});

// Apple receipt status kodlarını açıklayan yardımcı fonksiyon
function getReceiptStatusMessage(status) {
  const statusMessages = {
    0: 'Success',
    21000: 'The App Store could not read the JSON object you provided.',
    21002: 'The data in the receipt-data property was malformed or missing.',
    21003: 'The receipt could not be authenticated.',
    21004: 'The shared secret you provided does not match the shared secret on file for your account.',
    21005: 'The receipt server is not currently available.',
    21006: 'This receipt is valid but the subscription has expired.',
    21007: 'This receipt is from the test environment, but it was sent to the production environment for verification.',
    21008: 'This receipt is from the production environment, but it was sent to the test environment for verification.',
    21010: 'This receipt could not be authorized. Treat this the same as if a purchase was never made.',
    21100: 'Internal data access error.',
    21199: 'Unknown error.'
  };
  
  return statusMessages[status] || `Unknown status code: ${status}`;
}
