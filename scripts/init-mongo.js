// MongoDB initialization script
// This script runs when the MongoDB container starts for the first time

// Switch to the marcel_expenses database
db = db.getSiblingDB("marcel_expenses");

// Create a user for the application
db.createUser({
  user: "marcel_app",
  pwd: "marcel_app_password",
  roles: [
    {
      role: "readWrite",
      db: "marcel_expenses",
    },
  ],
});

// Create initial collections (optional)
db.createCollection("users");
db.createCollection("expenses");
db.createCollection("categories");
db.createCollection("budgets");
db.createCollection("settings");

print("Database initialization completed successfully!");
