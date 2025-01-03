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
const url = process.env.MONGODB_URI;
const dbName = 'mydatabase';
let mongoClient;
const appleSignin = require('apple-signin-auth');
const verifyReceipt = require('node-apple-receipt-verify');
const SUBSCRIPTION_TYPES = {
  MONTHLY: 'monthly_subscription',
  // Add other subscription types if needed
};

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
    retryWrites: true,
    useUnifiedTopology: true,
    maxPoolSize: 10,
  });
  await client.connect();
  dbInstance = client.db(dbName);
  console.log('Connected to MongoDB');
  return dbInstance;
}

// Add this middleware function before your routes
const requireActiveSubscription = async (req, res, next) => {
  try {
    // Extract userId from request (either from body, params, or auth token)
    const userId = req.body.userId || req.params.userId || req.query.userId;
    
    if (!userId) {
      return res.status(401).json({ error: 'User ID is required' });
    }

    const db = await connectDB();
    const subscription = await db.collection('subscriptions').findOne({
      userId: new ObjectId(userId),
      isActive: true,
      expirationDate: { $gt: new Date() }
    });

    if (!subscription) {
      return res.status(403).json({ 
        error: 'Active subscription required',
        message: 'Please subscribe to access this feature'
      });
    }

    // If subscription is valid, proceed to the next middleware/route handler
    next();
  } catch (error) {
    console.error('Subscription check error:', error);
    res.status(500).json({ error: 'Error checking subscription status' });
  }
};

app.post('/uemes171221', requireActiveSubscription, async (req, res) => {
  try {
    const { message, userId } = req.body;
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [{ role: "user", content: message }],
    });

    // Store the interaction in the database
    const db = await connectDB();
    await db.collection('aiInteractions').insertOne({
      userId: new ObjectId(userId),
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

    // Yeni kullanıcı oluştur
    const user = {
      email: email || verified.email, // Apple bazen email vermeyebilir
      name: name || 'Apple User',     // İsim opsiyonel
      appleId: verified.sub,          // Apple'ın unique user ID'si
      createdAt: new Date(),
      authProvider: 'apple'
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
      { _id: new ObjectId(userId) },
      { projection: { password: 0 } } // Hassas bilgileri hariç tut
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Subscription bilgisini de ekle
    const subscription = await db.collection('subscriptions').findOne({
      userId: new ObjectId(userId),
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
    
    // Input validation
    if (!preferences || Object.keys(preferences).length === 0) {
      return res.status(400).json({ error: 'Preferences data is required' });
    }

    const db = await connectDB();
    const collection = db.collection('preferences');
    
    // MongoDB ObjectId dönüşümünü kontrol et
    let userObjectId;
    try {
      userObjectId = new ObjectId(userId);
    } catch (error) {
      return res.status(400).json({ error: 'Invalid user ID format' });
    }

    // Update işlemini daha detaylı hale getir
    const result = await collection.updateOne(
      { userId: userObjectId },
      { 
        $set: {
          ...preferences,
          userId: userObjectId, // userId'yi tekrar ekle
          updatedAt: new Date()
        }
      },
      { 
        upsert: true,
        returnDocument: 'after' // Güncellenmiş dokümanı döndür
      }
    );

    // Update sonucunu kontrol et
    if (result.matchedCount === 0 && !result.upsertedId) {
      return res.status(404).json({ error: 'Failed to update preferences' });
    }

    // Güncellenmiş tercihleri al
    const updatedPreferences = await collection.findOne({ userId: userObjectId });

    // Başarılı yanıt döndür
    res.json({ 
      message: 'Preferences updated successfully',
      preferences: updatedPreferences
    });

  } catch (error) {
    console.error('Error updating preferences:', error);
    // Daha detaylı hata mesajı
    res.status(500).json({ 
      error: 'Error updating preferences',
      details: error.message,
      code: error.code
    });
  }
});

app.get('/preferences/:userId', requireActiveSubscription, async (req, res) => {
  try {
    const { userId } = req.params;
    const db = await connectDB();
    const collection = db.collection('preferences');
    
    const preferences = await collection.findOne({ userId: new ObjectId(userId) });
    
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
    
    if (!content || !userId || !mealType) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const db = await connectDB();
    const collection = db.collection('recipes');
    
    const recipe = {
      title,
      mealType,
      servings,
      content,
      userId: new ObjectId(userId),
      preferences,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const result = await collection.insertOne(recipe);
    res.status(201).json({ 
      message: 'Recipe saved successfully',
      recipeId: result.insertedId 
    });
  } catch (error) {
    console.error('Error saving recipe:', error);
    res.status(500).json({ error: 'Error saving recipe' });
  }
});

app.get('/recipes/:userId', requireActiveSubscription, async (req, res) => {
  try {
    const { userId } = req.params;
    const { mealType, page = 1, limit = 10 } = req.query;
    
    const db = await connectDB();
    const collection = db.collection('recipes');
    
    const query = { userId: new ObjectId(userId) };
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
      _id: new ObjectId(recipeId),
      userId: new ObjectId(userId)
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
        _id: new ObjectId(recipeId),
        userId: new ObjectId(userId)
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
      _id: new ObjectId(recipeId),
      userId: new ObjectId(userId)
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
      userId: new ObjectId(userId)
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
      { userId: new ObjectId(userId) },
      {
        $set: {
          userId: new ObjectId(userId),
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

app.get('/subscription-status/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const db = await connectDB();
    const subscriptionsCollection = db.collection('subscriptions');

    const subscription = await subscriptionsCollection.findOne({
      userId: new ObjectId(userId)
    });

    if (!subscription) {
      return res.json({
        isActive: false,
        message: 'No subscription found'
      });
    }

    // Check if subscription needs renewal verification
    const now = new Date();
    if (subscription.isActive && subscription.expirationDate < now) {
      // Verify with Apple again
      const validationData = await verifyReceipt.validate({ 
        receipt: subscription.receipt 
      });

      if (validationData.success) {
        const latestReceipt = validationData.latest_receipt_info[0];
        const newExpirationDate = new Date(parseInt(latestReceipt.expires_date_ms));
        const isStillValid = newExpirationDate > now;

        // Update subscription status
        await subscriptionsCollection.updateOne(
          { userId: new ObjectId(userId) },
          {
            $set: {
              expirationDate: newExpirationDate,
              isActive: isStillValid,
              updatedAt: now
            }
          }
        );

        return res.json({
          isActive: isStillValid,
          expirationDate: newExpirationDate
        });
      }
    }

    res.json({
      isActive: subscription.isActive,
      expirationDate: subscription.expirationDate
    });
  } catch (error) {
    console.error('Error checking subscription status:', error);
    res.status(500).json({ error: 'Error checking subscription status' });
  }
});

app.get('/feature-access/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const db = await connectDB();
    
    const subscription = await db.collection('subscriptions').findOne({
      userId: new ObjectId(userId),
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

process.on('SIGINT', async () => {
  try {
    await mongoClient.close();
    console.log('MongoDB connection closed.');
    process.exit(0);
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
