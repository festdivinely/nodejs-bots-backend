import mongoose from 'mongoose';

export const BotMarket = {
    OPTIONS: 'options',
    FUTURES: 'futures',
    STOCKS: 'stocks',
    CRYPTO: 'crypto',
    FOREX: 'forex',
};

export const PlatformType = {
    DERIV: 'deriv',
    IQ_OPTION: 'iq_option',
    BINANCE: 'binance',
    COINBASE: 'coinbase',
    OANDA: 'oanda',
    INTERACTIVE_BROKERS: 'interactive_brokers',
};

const BotTemplateSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: [true, 'Bot name is required'],
            unique: true,
            trim: true,
        },
        market: {
            type: String,
            enum: Object.values(BotMarket),
            required: [true, 'Market type is required'],
        },
        description: {
            type: String,
            required: [true, 'Description is required'],
            trim: true,
        },
        image: {
            type: String,
            default: '',
        },
        efficiency: {
            type: Number,
            min: [0, 'Efficiency cannot be negative'],
            max: [100, 'Efficiency cannot exceed 100'],
        },
        risk: {
            type: String,
            enum: ['low', 'medium', 'high'],
            default: 'medium',
            lowercase: true,
        },
        isFree: {
            type: Boolean,
            default: false,
        },
        price: {
            type: Number,
            default: 0,
            min: [0, 'Price cannot be negative'],
        },
        platform: {
            type: String,
            enum: Object.values(PlatformType),
            required: [true, 'A single broker platform is required'],
        },
        botData: {
            type: mongoose.Schema.Types.Mixed,
            default: {},
            validate: {
                validator: function (v) {
                    return typeof v === 'object' && v !== null;
                },
                message: 'botData must be an object',
            },
        },
        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: [true, 'Creator is required'],
        },
    },
    {
        timestamps: true,
        toJSON: { virtuals: true },
        toObject: { virtuals: true },
    }
);

// Virtual for id to match string id format
BotTemplateSchema.virtual('id').get(function () {
    return this._id.toHexString();
});

// Export the Mongoose model as default
export default mongoose.model('BotTemplate', BotTemplateSchema);