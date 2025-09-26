import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Marcel Expenses API',
      version: '1.0.0',
      description: `
        A comprehensive expense management API for tracking personal and business expenses.
        
        ## Features
        - User authentication and authorization
        - Expense tracking and categorization
        - Budget management and monitoring
        - Advanced reporting and analytics
        - Google Maps integration for location-based expenses
        - AI-powered expense insights
        
        ## Authentication
        This API uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:
        \`Authorization: Bearer <your-jwt-token>\`
        
        ## Rate Limiting
        API endpoints are rate-limited to prevent abuse. Standard limits apply unless otherwise specified.
      `,
      contact: {
        name: 'Marcel Expenses Support',
        email: 'support@marcel-expenses.com'
      },
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT'
      }
    },
    servers: [
      {
        url: process.env.BASE_URL || 'http://localhost:5000',
        description: 'Development server'
      },
      {
        url: 'https://api.marcel-expenses.com',
        description: 'Production server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Enter JWT token obtained from login endpoint'
        },
        cookieAuth: {
          type: 'apiKey',
          in: 'cookie',
          name: 'token',
          description: 'JWT token stored in HTTP-only cookie'
        }
      },
      schemas: {
        // User schemas
        User: {
          type: "object",
          properties: {
            _id: {
              type: "string",
              description: "User ID",
              example: "60d5ecb74b24a1234567890a",
            },
            name: {
              type: "string",
              description: "User's full name",
              example: "John Doe",
            },
            email: {
              type: "string",
              format: "email",
              description: "User's email address",
              example: "john.doe@example.com",
            },
            role: {
              type: "string",
              enum: ["admin", "sales_rep"],
              description: "User role",
              example: "sales_rep",
            },
            status: {
              type: "string",
              enum: ["active", "inactive"],
              description: "User account status",
              example: "active",
            },
            createdAt: {
              type: "string",
              format: "date-time",
              description: "Account creation date",
              example: "2024-01-15T10:30:00Z",
            },
            updatedAt: {
              type: "string",
              format: "date-time",
              description: "Last update date",
              example: "2024-01-15T10:30:00Z",
            },
          },
        },
        UserProfile: {
          type: "object",
          properties: {
            id: {
              type: "string",
              description: "User ID",
              example: "60d5ecb74b24a1234567890a",
            },
            name: {
              type: "string",
              description: "User's full name",
              example: "John Doe",
            },
            email: {
              type: "string",
              format: "email",
              description: "User's email address",
              example: "john.doe@example.com",
            },
            role: {
              type: "string",
              enum: ["admin", "sales_rep"],
              description: "User role",
              example: "sales_rep",
            },
          },
        },

        // Category schemas
        Category: {
          type: "object",
          properties: {
            _id: {
              type: "string",
              description: "Category ID",
              example: "60d5ecb74b24a1234567890b",
            },
            name: {
              type: "string",
              description: "Category name",
              example: "Business Travel",
            },
            description: {
              type: "string",
              description: "Category description",
              example: "Expenses related to business travel and transportation",
            },
            color: {
              type: "string",
              description: "Category color for UI display",
              example: "#3B82F6",
            },
            isActive: {
              type: "boolean",
              description: "Whether the category is active",
              example: true,
            },
            budgetLimits: {
              type: "array",
              items: {
                $ref: "#/components/schemas/BudgetLimit",
              },
            },
            createdAt: {
              type: "string",
              format: "date-time",
              example: "2024-01-15T10:30:00Z",
            },
            updatedAt: {
              type: "string",
              format: "date-time",
              example: "2024-01-15T10:30:00Z",
            },
          },
        },

        // Budget schemas
        Budget: {
          type: "object",
          properties: {
            _id: {
              type: "string",
              description: "Budget ID",
              example: "60d5ecb74b24a1234567890c",
            },
            name: {
              type: "string",
              description: "Budget name",
              example: "Q1 2024 Travel Budget",
            },
            description: {
              type: "string",
              description: "Budget description",
              example: "Quarterly budget for business travel expenses",
            },
            amount: {
              type: "number",
              description: "Budget amount",
              example: 5000.00,
            },
            period: {
              type: "string",
              enum: ["monthly", "quarterly", "yearly"],
              description: "Budget period",
              example: "quarterly",
            },
            startDate: {
              type: "string",
              format: "date",
              description: "Budget start date",
              example: "2024-01-01",
            },
            endDate: {
              type: "string",
              format: "date",
              description: "Budget end date",
              example: "2024-03-31",
            },
            categories: {
              type: "array",
              items: {
                type: "string",
              },
              description: "Associated category IDs",
              example: ["60d5ecb74b24a1234567890b"],
            },
            spent: {
              type: "number",
              description: "Amount spent from budget",
              example: 1250.50,
            },
            remaining: {
              type: "number",
              description: "Remaining budget amount",
              example: 3749.50,
            },
            createdBy: {
              type: "string",
              description: "User ID who created the budget",
              example: "60d5ecb74b24a1234567890a",
            },
            createdAt: {
              type: "string",
              format: "date-time",
              example: "2024-01-15T10:30:00Z",
            },
            updatedAt: {
              type: "string",
              format: "date-time",
              example: "2024-01-15T10:30:00Z",
            },
          },
        },
        BudgetLimit: {
          type: "object",
          properties: {
            _id: {
              type: "string",
              description: "Budget limit ID",
              example: "60d5ecb74b24a1234567890d",
            },
            period: {
              type: "string",
              enum: ["daily", "weekly", "monthly", "yearly"],
              description: "Budget period",
              example: "monthly",
            },
            amount: {
              type: "number",
              description: "Budget limit amount",
              example: 1000.00,
            },
            spent: {
              type: "number",
              description: "Amount spent in current period",
              example: 250.75,
            },
            remaining: {
              type: "number",
              description: "Remaining budget amount",
              example: 749.25,
            },
            startDate: {
              type: "string",
              format: "date",
              description: "Period start date",
              example: "2024-01-01",
            },
            endDate: {
              type: "string",
              format: "date",
              description: "Period end date",
              example: "2024-01-31",
            },
          },
        },

        // Expense schemas
        Expense: {
          type: "object",
          properties: {
            _id: {
              type: "string",
              description: "Expense ID",
              example: "60d5ecb74b24a1234567890e",
            },
            category: {
              $ref: "#/components/schemas/Category",
            },
            startingPoint: {
              type: "string",
              description: "Journey starting point",
              example: "Downtown Office",
            },
            destinationPoint: {
              type: "string",
              description: "Journey destination",
              example: "Client Meeting - Uptown",
            },
            startingPointPlaceId: {
              type: "string",
              description: "Google Places ID for starting point",
              example: "ChIJN1t_tDeuEmsRUsoyG83frY4",
            },
            destinationPointPlaceId: {
              type: "string",
              description: "Google Places ID for destination",
              example: "ChIJP3Sa8ziYEmsRUKgyFmh9AQM",
            },
            formattedStartingAddress: {
              type: "string",
              description: "Formatted starting address",
              example: "123 Business St, Downtown, City 12345",
            },
            formattedDestinationAddress: {
              type: "string",
              description: "Formatted destination address",
              example: "456 Client Ave, Uptown, City 67890",
            },
            waypoints: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  placeId: {
                    type: "string",
                    description: "Google Places ID for waypoint",
                  },
                  address: {
                    type: "string",
                    description: "Waypoint address",
                  },
                },
              },
            },
            distance: {
              type: "number",
              description: "Journey distance in kilometers",
              example: 15.5,
            },
            costPerKm: {
              type: "number",
              description: "Cost per kilometer",
              example: 0.65,
            },
            totalCost: {
              type: "number",
              description: "Total expense cost",
              example: 10.08,
            },
            journeyDate: {
              type: "string",
              format: "date-time",
              description: "Date and time of journey",
              example: "2024-01-15T09:00:00Z",
            },
            notes: {
              type: "string",
              description: "Additional notes about the expense",
              example: "Client meeting for project discussion",
            },
            enhancedNotes: {
              type: "string",
              description: "AI-enhanced notes",
              example: "Business trip from Downtown Office to Client Meeting - Uptown on January 15, 2024. Purpose: Client meeting for project discussion.",
            },
            createdBy: {
              type: "string",
              description: "User ID who created the expense",
              example: "60d5ecb74b24a1234567890a",
            },
            createdAt: {
              type: "string",
              format: "date-time",
              example: "2024-01-15T10:30:00Z",
            },
            updatedAt: {
              type: "string",
              format: "date-time",
              example: "2024-01-15T10:30:00Z",
            },
          },
        },
        ExpenseWithRoute: {
          allOf: [
            {
              $ref: "#/components/schemas/Expense",
            },
            {
              type: "object",
              properties: {
                routeData: {
                  type: "object",
                  properties: {
                    coordinates: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          lat: {
                            type: "number",
                            example: 40.7128,
                          },
                          lng: {
                            type: "number",
                            example: -74.0060,
                          },
                        },
                      },
                    },
                    bounds: {
                      type: "object",
                      properties: {
                        north: { type: "number" },
                        south: { type: "number" },
                        east: { type: "number" },
                        west: { type: "number" },
                      },
                    },
                  },
                },
              },
            },
          ],
        },
        CreateExpenseRequest: {
          type: "object",
          required: [
            "category",
            "startingPoint",
            "destinationPoint",
            "journeyDate",
          ],
          properties: {
            category: {
              type: "string",
              description: "Category ID",
              example: "60d5ecb74b24a1234567890b",
            },
            startingPoint: {
              type: "string",
              minLength: 2,
              maxLength: 100,
              description: "Journey starting point",
              example: "Downtown Office",
            },
            destinationPoint: {
              type: "string",
              minLength: 2,
              maxLength: 100,
              description: "Journey destination",
              example: "Client Meeting - Uptown",
            },
            startingPointPlaceId: {
              type: "string",
              description: "Google Places ID for starting point (optional)",
              example: "ChIJN1t_tDeuEmsRUsoyG83frY4",
            },
            destinationPointPlaceId: {
              type: "string",
              description: "Google Places ID for destination (optional)",
              example: "ChIJP3Sa8ziYEmsRUKgyFmh9AQM",
            },
            formattedStartingAddress: {
              type: "string",
              description: "Formatted starting address (optional)",
              example: "123 Business St, Downtown, City 12345",
            },
            formattedDestinationAddress: {
              type: "string",
              description: "Formatted destination address (optional)",
              example: "456 Client Ave, Uptown, City 67890",
            },
            waypoints: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  placeId: {
                    type: "string",
                    description: "Google Places ID for waypoint",
                  },
                  address: {
                    type: "string",
                    description: "Waypoint address",
                  },
                },
              },
            },
            distance: {
              type: "number",
              minimum: 0.1,
              description: "Journey distance in kilometers (required if place IDs not provided)",
              example: 15.5,
            },
            costPerKm: {
              type: "number",
              minimum: 0.01,
              description: "Cost per kilometer (required if place IDs not provided)",
              example: 0.65,
            },
            journeyDate: {
              type: "string",
              format: "date-time",
              description: "Date and time of journey",
              example: "2024-01-15T09:00:00Z",
            },
            notes: {
              type: "string",
              maxLength: 1000,
              description: "Additional notes about the expense",
              example: "Client meeting for project discussion",
            },
          },
        },
        UpdateExpenseRequest: {
          type: "object",
          properties: {
            category: {
              type: "string",
              description: "Category ID",
              example: "60d5ecb74b24a1234567890b",
            },
            startingPoint: {
              type: "string",
              minLength: 2,
              maxLength: 100,
              description: "Journey starting point",
              example: "Downtown Office",
            },
            destinationPoint: {
              type: "string",
              minLength: 2,
              maxLength: 100,
              description: "Journey destination",
              example: "Client Meeting - Uptown",
            },
            startingPointPlaceId: {
              type: "string",
              description: "Google Places ID for starting point",
              example: "ChIJN1t_tDeuEmsRUsoyG83frY4",
            },
            destinationPointPlaceId: {
              type: "string",
              description: "Google Places ID for destination",
              example: "ChIJP3Sa8ziYEmsRUKgyFmh9AQM",
            },
            formattedStartingAddress: {
              type: "string",
              description: "Formatted starting address",
              example: "123 Business St, Downtown, City 12345",
            },
            formattedDestinationAddress: {
              type: "string",
              description: "Formatted destination address",
              example: "456 Client Ave, Uptown, City 67890",
            },
            waypoints: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  placeId: {
                    type: "string",
                    description: "Google Places ID for waypoint",
                  },
                  address: {
                    type: "string",
                    description: "Waypoint address",
                  },
                },
              },
            },
            distance: {
              type: "number",
              minimum: 0.1,
              description: "Journey distance in kilometers",
              example: 15.5,
            },
            costPerKm: {
              type: "number",
              minimum: 0.01,
              description: "Cost per kilometer",
              example: 0.65,
            },
            journeyDate: {
              type: "string",
              format: "date-time",
              description: "Date and time of journey",
              example: "2024-01-15T09:00:00Z",
            },
            notes: {
              type: "string",
              maxLength: 1000,
              description: "Additional notes about the expense",
              example: "Client meeting for project discussion",
            },
          },
        },

        // Pagination schema
        Pagination: {
          type: "object",
          properties: {
            page: {
              type: "integer",
              description: "Current page number",
              example: 1,
            },
            limit: {
              type: "integer",
              description: "Number of items per page",
              example: 10,
            },
            totalPages: {
              type: "integer",
              description: "Total number of pages",
              example: 5,
            },
            totalCount: {
              type: "integer",
              description: "Total number of items",
              example: 47,
            },
            hasNextPage: {
              type: "boolean",
              description: "Whether there is a next page",
              example: true,
            },
            hasPrevPage: {
              type: "boolean",
              description: "Whether there is a previous page",
              example: false,
            },
          },
        },

        // Common response schemas
        Error: {
          type: "object",
          properties: {
            success: {
              type: "boolean",
              example: false,
            },
            error: {
              type: "string",
              description: "Error message",
            },
          },
        },
        ValidationError: {
          type: "object",
          properties: {
            success: {
              type: "boolean",
              example: false,
            },
            error: {
              type: "string",
              description: "Validation error message",
            },
            details: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  field: {
                    type: "string",
                    description: "Field that failed validation",
                  },
                  message: {
                    type: "string",
                    description: "Validation error message",
                  },
                },
              },
            },
          },
        }
      },
      
      responses: {
        UnauthorizedError: {
          description: 'Authentication required',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/Error'
              },
              example: {
                success: false,
                error: 'Not authorized to access this route',
                statusCode: 401,
                timestamp: '2024-01-15T10:30:00.000Z'
              }
            }
          }
        },
        
        ForbiddenError: {
          description: 'Insufficient permissions',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/Error'
              },
              example: {
                success: false,
                error: 'Forbidden - insufficient permissions',
                statusCode: 403,
                timestamp: '2024-01-15T10:30:00.000Z'
              }
            }
          }
        },
        
        NotFoundError: {
          description: 'Resource not found',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/Error'
              },
              example: {
                success: false,
                error: 'Resource not found',
                statusCode: 404,
                timestamp: '2024-01-15T10:30:00.000Z'
              }
            }
          }
        },
        
        ValidationError: {
          description: 'Validation error',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/Error'
              },
              example: {
                success: false,
                error: 'Validation failed',
                statusCode: 400,
                timestamp: '2024-01-15T10:30:00.000Z'
              }
            }
          }
        },
        
        ServerError: {
          description: 'Internal server error',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/Error'
              },
              example: {
                success: false,
                error: 'Internal server error',
                statusCode: 500,
                timestamp: '2024-01-15T10:30:00.000Z'
              }
            }
          }
        }
      }
    },
    
    security: [
      {
        bearerAuth: []
      }
    ],
    
    tags: [
      {
        name: 'Authentication',
        description: 'User authentication and authorization endpoints'
      },
      {
        name: 'Users',
        description: 'User management endpoints'
      },
      {
        name: 'Expenses',
        description: 'Expense tracking and management endpoints'
      },
      {
        name: 'Categories',
        description: 'Expense category management endpoints'
      },
      {
        name: 'Budgets',
        description: 'Budget management and monitoring endpoints'
      },
      {
        name: 'Reports',
        description: 'Reporting and analytics endpoints'
      },
      {
        name: 'Maps',
        description: 'Location and mapping services endpoints'
      },
      {
        name: 'Settings',
        description: 'Application settings and configuration endpoints'
      }
    ]
  },
  apis: [
    './src/routes/*.js',
    './src/models/*.js',
    './src/controllers/*.js'
  ]
};

const specs = swaggerJsdoc(options);

export { specs, swaggerUi };