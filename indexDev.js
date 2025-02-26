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

// Configure receipt verification
verifyReceipt.config({
  secret: process.env.APPLE_SHARED_SECRET, // From App Store Connect
  environment: process.env.NODE_ENV === 'production' ? 'production' : 'sandbox'
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
    // userId'yi daha kapsamlı bir şekilde kontrol edelim
    const userId = req.params.userId || req.body.userId || req.query.userId;
    
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
    
    const subscription = await db.collection('subscriptions').findOne({
      userId: ObjectId.createFromHexString(userId),
      isActive: true,
      $or: [
        { expirationDate: { $gt: new Date() } },
        { trialPeriod: true }
      ]
    });

    console.log('Subscription status:', subscription ? 'Active' : 'Inactive');

    if (!subscription) {
      return res.status(403).json({ 
        error: 'Active subscription required',
        details: 'No active subscription found'
      });
    }

    // Add subscription to request object for later use
    req.subscription = subscription;
    next();
  } catch (error) {
    console.error('Subscription check error:', error);
    res.status(500).json({ 
      error: 'Error checking subscription',
      details: error.message 
    });
  }
};

// AI endpoint'ini güncelleyelim - middleware'i kullanarak sadeleştirelim
app.post('/uemes171221', requireActiveSubscription, async (req, res) => {
  try {
    const { message, userId } = req.body;
    
    // Input validation
    if (!message) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        details: 'Message is required'
      });
    }

    // Middleware zaten subscription kontrolü yaptı, req.subscription'ı kullanabiliriz
    const db = await connectDB();
    const user = await db.collection('users').findOne(
      { _id: ObjectId.createFromHexString(userId) }
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Trial period checks - middleware'den gelen subscription bilgisini kullan
    if (req.subscription.trialPeriod) {
      const trialCount = user.trialRecipeCount || 0;
      if (trialCount >= TRIAL_MAX_RECIPES) {
        return res.status(403).json({ 
          error: 'Trial limit reached',
          details: 'Please upgrade to continue generating recipes'
        });
      }
    }

    // Generate AI response
    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [{ role: "user", content: message }],
    });

    // Log interaction
    await db.collection('aiInteractions').insertOne({
      userId: ObjectId.createFromHexString(userId),
      message,
      response: completion.choices[0].message.content,
      timestamp: new Date(),
      subscriptionType: req.subscription.trialPeriod ? 'trial' : 'paid'
    });

    // Update trial count if needed
    if (req.subscription.trialPeriod) {
      await db.collection('users').updateOne(
        { _id: ObjectId.createFromHexString(userId) },
        { $inc: { trialRecipeCount: 1 } }
      );
    }

    res.json({ 
      response: completion.choices[0].message.content,
      remainingTrialRequests: req.subscription.trialPeriod ? 
        TRIAL_MAX_RECIPES - (user.trialRecipeCount + 1) : 
        'unlimited'
    });

  } catch (error) {
    console.error('AI Generation Error:', error);
    res.status(500).json({ 
      error: 'Error processing request',
      details: error.message
    });
  }
});

app.post('/register', async (req, res) => {
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
      userId: result.insertedId,
      isActive: true,
      trialPeriod: true,
      startDate: new Date(),
      expirationDate: new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)), // 7 günlük deneme
      createdAt: new Date()
    });

    res.status(201).json({ 
      message: 'User registered successfully',
      userId: result.insertedId 
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

app.post('/preferences/:userId', requireActiveSubscription, async (req, res) => {
  try {
    const { userId } = req.params;
    const preferences = req.body;
    
    // Gelen tercihlerin boş olmadığını kontrol et
    if (!preferences || Object.keys(preferences).length === 0) {
      return res.status(400).json({ error: 'Preferences data is required' });
    }

    // Geçerli bir ObjectId olduğunu kontrol et
    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    const db = await connectDB();
    const collection = db.collection('preferences');
    
    // Kullanıcının var olduğunu kontrol et
    const userExists = await db.collection('users').findOne({ _id: ObjectId.createFromHexString(userId) });
    if (!userExists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const result = await collection.updateOne(
      { userId: ObjectId.createFromHexString(userId) },
      { 
        $set: { 
          ...preferences,
          updatedAt: new Date(),
          userId: ObjectId.createFromHexString(userId) // userId'yi de preferences içinde saklayalım
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

app.get('/preferences/:userId', requireActiveSubscription, async (req, res) => {
  try {
    const { userId } = req.params;
    const db = await connectDB();
    const collection = db.collection('preferences');
    
    const preferences = await collection.findOne({ userId: ObjectId.createFromHexString(userId) });
    
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
    const { title, mealType, servings, content, userId, preferences } = req.body;
    
    // userId kontrolünü daha detaylı yapalım
    if (!userId) {
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
      const userObjectId = ObjectId.createFromHexString(userId);
      
      const recipe = {
        title,
        mealType,
        servings,
        content,
        userId: userObjectId,
        preferences,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      const result = await collection.insertOne(recipe);
      console.log('Recipe saved successfully for userId:', userId);
      
      res.status(201).json({ 
        success: true,
        message: 'Recipe saved successfully',
        recipeId: result.insertedId 
      });
    } catch (idError) {
      console.error('Invalid userId format:', userId);
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

app.get('/recipes/:userId', requireActiveSubscription, async (req, res) => {
  try {
    const { userId } = req.params;
    const { mealType, page = 1, limit = 10 } = req.query;
    
    const db = await connectDB();
    const collection = db.collection('recipes');
    
    const query = { userId: ObjectId.createFromHexString(userId) };
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

app.get('/recipes/:userId/:recipeId', requireActiveSubscription, async (req, res) => {
  try {
    const { userId, recipeId } = req.params;
    
    const db = await connectDB();
    const collection = db.collection('recipes');
    
    const recipe = await collection.findOne({
      _id: ObjectId.createFromHexString(recipeId),
      userId: ObjectId.createFromHexString(userId)
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
    const { userId, recipeId } = req.params;
    const updateData = req.body;
    
    delete updateData._id; // Prevent _id modification
    delete updateData.userId; // Prevent userId modification
    
    const db = await connectDB();
    const collection = db.collection('recipes');
    
    const result = await collection.updateOne(
      {
        _id: ObjectId.createFromHexString(recipeId),
        userId: ObjectId.createFromHexString(userId)
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

app.delete('/recipes/:userId/:recipeId', requireActiveSubscription, async (req, res) => {
  try {
    const { userId, recipeId } = req.params;
    
    const db = await connectDB();
    const collection = db.collection('recipes');
    
    const result = await collection.deleteOne({
      _id: ObjectId.createFromHexString(recipeId),
      userId: ObjectId.createFromHexString(userId)
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

app.get('/recipes/:userId/search', requireActiveSubscription, async (req, res) => {
  try {
    const { userId } = req.params;
    const { query, mealType, page = 1, limit = 10 } = req.query;
    
    const db = await connectDB();
    const collection = db.collection('recipes');
    
    const searchQuery = {
      userId: ObjectId.createFromHexString(userId)
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

app.post('/verify-subscription', async (req, res) => {
  try {
    const { userId, receipt, productId } = req.body;
    
    if (!userId || !receipt || !productId) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Verify receipt with Apple
    const validationData = await verifyReceipt.validate({ receipt });
    
    if (!validationData.success) {
      return res.status(400).json({ error: 'Invalid receipt' });
    }

    const latestReceipt = validationData.latest_receipt_info[0];
    
    // Check if the subscription is still valid
    const expirationDate = new Date(parseInt(latestReceipt.expires_date_ms));
    const isValid = expirationDate > new Date();

    const db = await connectDB();
    const subscriptionsCollection = db.collection('subscriptions');

    // Save or update subscription information
    await subscriptionsCollection.updateOne(
      { userId: ObjectId.createFromHexString(userId) },
      {
        $set: {
          userId: ObjectId.createFromHexString(userId),
          productId,
          originalTransactionId: latestReceipt.original_transaction_id,
          latestTransactionId: latestReceipt.transaction_id,
          expirationDate,
          isActive: isValid,
          receipt: receipt,
          updatedAt: new Date()
        }
      },
      { upsert: true }
    );

    res.json({
      success: true,
      expirationDate,
      isActive: isValid
    });
  } catch (error) {
    console.error('Subscription verification error:', error);
    res.status(500).json({ error: 'Error verifying subscription' });
  }
});

// Subscription status endpoint'ini de kontrol edelim
app.get('/subscription-status/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const db = await connectDB();
    
    const subscription = await db.collection('subscriptions').findOne({
      userId: ObjectId.createFromHexString(userId),
      isActive: true,
      $or: [
        { expirationDate: { $gt: new Date() } },
        { trialPeriod: true }
      ]
    });

    console.log('Subscription check for userId:', userId, 'Result:', subscription);

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
    const { userId } = req.params;
    const db = await connectDB();
    
    const subscription = await db.collection('subscriptions').findOne({
      userId: ObjectId.createFromHexString(userId),
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

app.delete('/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({ error: 'Invalid user ID format' });
    }

    const db = await connectDB();
    const userObjectId = ObjectId.createFromHexString(userId);

    // Kullanıcıyı kontrol et
    const user = await db.collection('users').findOne({ _id: userObjectId });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // RevenueCat aboneliğini kontrol et
    const subscription = await db.collection('subscriptions').findOne({
      userId: userObjectId,
      isActive: true
    });

    if (subscription) {
      try {
        // RevenueCat'te aboneliği iptal et
        await axios.post(`https://api.revenuecat.com/v1/subscribers/${userId}/revoke`, null, {
          headers: {
            'Authorization': `Bearer ${REVENUECAT_API_KEY}`,
            'Content-Type': 'application/json'
          }
        });
      } catch (revenueCatError) {
        console.error('RevenueCat error:', revenueCatError);
        // RevenueCat hatası olsa bile devam et
      }
    }

    // Kullanıcı ve ilgili tüm verileri sil
    await Promise.all([
      db.collection('users').deleteOne({ _id: userObjectId }),
      db.collection('preferences').deleteOne({ userId: userObjectId }),
      db.collection('recipes').deleteMany({ userId: userObjectId }),
      db.collection('subscriptions').deleteMany({ userId: userObjectId }),
      db.collection('aiInteractions').deleteMany({ userId: userObjectId })
    ]);

    res.json({ success: true });
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
    const event = req.body;
    const db = await connectDB();

    // Webhook event'inin geçerliliğini kontrol et
    if (!event.type || !event.app_user_id) {
      return res.status(400).json({ error: 'Invalid webhook payload' });
    }

    switch (event.type) {
      case 'INITIAL_PURCHASE':
      case 'RENEWAL':
        await db.collection('subscriptions').updateOne(
          { userId: ObjectId.createFromHexString(event.app_user_id) },
          {
            $set: {
              isActive: true,
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
      case 'EXPIRATION':
        await db.collection('subscriptions').updateOne(
          { userId: ObjectId.createFromHexString(event.app_user_id) },
          {
            $set: {
              isActive: false,
              updatedAt: new Date(),
              lastWebhookEvent: event.type,
              lastWebhookTimestamp: new Date()
            }
          }
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

// Apple receipt validation endpoint
app.post('/validate-receipt', async (req, res) => {
  try {
    const { receipt, userId } = req.body;
    
    // Önce production'da dene
    let validationResponse = await validateReceipt(receipt, false);
    
    // Eğer sandbox receipt hatası alırsak, sandbox'da dene
    if (validationResponse.status === 21007) {
      validationResponse = await validateReceipt(receipt, true);
    }

    const db = await connectDB();
    
    if (validationResponse.status === 0) {
      // Başarılı validation
      const latestReceipt = validationResponse.latest_receipt_info[0];
      
      await db.collection('subscriptions').updateOne(
        { userId: ObjectId.createFromHexString(userId) },
        {
          $set: {
            isActive: true,
            productId: latestReceipt.product_id,
            expirationDate: new Date(latestReceipt.expires_date_ms),
            environment: validationResponse.environment,
            updatedAt: new Date()
          }
        },
        { upsert: true }
      );

      res.json({
        isValid: true,
        expirationDate: new Date(latestReceipt.expires_date_ms)
      });
    } else {
      res.json({
        isValid: false,
        status: validationResponse.status
      });
    }
  } catch (error) {
    console.error('Receipt validation error:', error);
    res.status(500).json({ error: 'Receipt validation failed' });
  }
});

async function validateReceipt(receipt, isSandbox) {
  const endpoint = isSandbox
    ? 'https://sandbox.itunes.apple.com/verifyReceipt'
    : 'https://buy.itunes.apple.com/verifyReceipt';

  const response = await axios.post(endpoint, {
    'receipt-data': receipt,
    'password': APPLE_SHARED_SECRET,
    'exclude-old-transactions': true
  });

  return response.data;
}
