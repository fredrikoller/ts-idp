import { v4 as uuidv4 } from 'uuid';

interface User {
    id: string;
    email: string; 
    passwordHash: string;
    salt: string;
}

const users: User[] = [];

function generateSalt(): string {
    return uuidv4();
}

function generateHash(password: string, salt: string): string {
    // In a real application, you would use a secure hashing algorithm like bcrypt or Argon2
    return password + salt; // Placeholder for demonstration purposes
}