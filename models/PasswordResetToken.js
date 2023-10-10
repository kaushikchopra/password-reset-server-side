import mongoose from 'mongoose';

const passwordResetTokenSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    token: String,
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 3600
    }
})

const PasswordResetToken = new mongoose.model('PasswordResetToken', passwordResetTokenSchema)

export { PasswordResetToken };