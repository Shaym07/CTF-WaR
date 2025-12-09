-- CTF War v4.0 Migration Script
-- Run this in Supabase SQL Editor to add new columns

-- Add new columns to challenges table
ALTER TABLE challenges ADD COLUMN IF NOT EXISTS scoring_type TEXT DEFAULT 'static';
ALTER TABLE challenges ADD COLUMN IF NOT EXISTS initial_points INTEGER;
ALTER TABLE challenges ADD COLUMN IF NOT EXISTS minimum_points INTEGER DEFAULT 50;
ALTER TABLE challenges ADD COLUMN IF NOT EXISTS decay INTEGER DEFAULT 15;
ALTER TABLE challenges ADD COLUMN IF NOT EXISTS flag_type TEXT DEFAULT 'static';
ALTER TABLE challenges ADD COLUMN IF NOT EXISTS case_sensitive BOOLEAN DEFAULT true;
ALTER TABLE challenges ADD COLUMN IF NOT EXISTS prerequisites TEXT[] DEFAULT '{}';
ALTER TABLE challenges ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT '{}';
ALTER TABLE challenges ADD COLUMN IF NOT EXISTS max_attempts INTEGER;
ALTER TABLE challenges ADD COLUMN IF NOT EXISTS type TEXT DEFAULT 'standard';
ALTER TABLE challenges ADD COLUMN IF NOT EXISTS state TEXT DEFAULT 'visible';

-- Add new columns to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS bracket_id UUID;
ALTER TABLE users ADD COLUMN IF NOT EXISTS affiliation TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS country TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS website TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS hidden BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;

-- Add new columns to teams table
ALTER TABLE teams ADD COLUMN IF NOT EXISTS invite_code TEXT;
ALTER TABLE teams ADD COLUMN IF NOT EXISTS affiliation TEXT;
ALTER TABLE teams ADD COLUMN IF NOT EXISTS country TEXT;
ALTER TABLE teams ADD COLUMN IF NOT EXISTS website TEXT;
ALTER TABLE teams ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT false;
ALTER TABLE teams ADD COLUMN IF NOT EXISTS hidden BOOLEAN DEFAULT false;

-- Add new columns to solves table
ALTER TABLE solves ADD COLUMN IF NOT EXISTS first_blood BOOLEAN DEFAULT false;

-- Create new tables if they don't exist
CREATE TABLE IF NOT EXISTS brackets (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pages (
    id UUID PRIMARY KEY,
    title TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    content TEXT,
    published BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS writeups (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    challenge_id UUID REFERENCES challenges(id),
    title TEXT NOT NULL,
    content TEXT,
    likes INTEGER DEFAULT 0,
    approved BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS writeup_likes (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    writeup_id UUID REFERENCES writeups(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, writeup_id)
);

CREATE TABLE IF NOT EXISTS achievements (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    achievement_id TEXT NOT NULL,
    points INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, achievement_id)
);

CREATE TABLE IF NOT EXISTS hint_unlocks (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    hint_id UUID REFERENCES hints(id),
    cost INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, hint_id)
);

-- Update existing challenges to have initial_points = points
UPDATE challenges SET initial_points = points WHERE initial_points IS NULL;
UPDATE challenges SET state = 'visible' WHERE state IS NULL;

-- Set hidden = false for all existing users and teams
UPDATE users SET hidden = false WHERE hidden IS NULL;
UPDATE users SET banned = false WHERE banned IS NULL;
UPDATE teams SET hidden = false WHERE hidden IS NULL;
UPDATE teams SET banned = false WHERE banned IS NULL;

-- Generate invite codes for existing teams
UPDATE teams SET invite_code = LEFT(gen_random_uuid()::text, 8) WHERE invite_code IS NULL;
