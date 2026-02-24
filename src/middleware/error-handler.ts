import { Request, Response, NextFunction } from "express";

export const errorHandlerMiddleware = (err: any, req: Request, res: Response, next: NextFunction) => {
    const statusCode = err.statusCode || 500;

    const response = {
        message: err.message || "Internal Server Error",
        ...(process.env.NODE_ENV === "development" && { stack: err.stack }),
    };

    console.error(`[${req.method}] ${req.path} >> ${err.message}`);

    res.status(statusCode).json(response);
};

export class AppError extends Error {
    public readonly statusCode: number;
    public readonly status: string;
    public readonly isOperational: boolean;

    constructor(message: string, statusCode: number) {
        super(message);

        this.statusCode = statusCode;
        this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
        this.isOperational = true;

        Error.captureStackTrace(this, this.constructor);
    }
}