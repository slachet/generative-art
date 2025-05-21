class Mold {
  constructor() {
    // Mold variables
    this.x = random(width);
    this.y = random(height);
    this.r = 0.1; // Thin lines
    
    this.heading = random(360);
    this.vx = cos(this.heading);
    this.vy = sin(this.heading);
    this.rotAngle = 10; // Smaller rotation angle for smoother curves
    
    // Sensor variables
    this.rSensorPos = createVector(0, 0);
    this.lSensorPos = createVector(0, 0);
    this.fSensorPos = createVector(0, 0);
    this.sensorAngle = 90;
    this.sensorDist = 150;
    
    // Trail variables
    this.trail = [];
    this.maxTrailLength = 10;
    this.trailColor = color(180, 180, 200, 100); // Darker, semi-transparent
    
    // Speed control
    this.speed = 2; // Slower movement
    
    // Branch control
    this.shouldBranch = false;
    this.branchChance = 0.002;
    
    // Track if position wraps around canvas edges
    this.wrapped = false;
  }
  
  update() {   
    this.vx = cos(this.heading) * this.speed;
    this.vy = sin(this.heading) * this.speed;
    
    // Previous position for edge detection
    let prevX = this.x;
    let prevY = this.y;
    
    // Update position with wrapping
    this.x = (this.x + this.vx + width) % width;
    this.y = (this.y + this.vy + height) % height;
    
    // Detect if we wrapped around the edges
    this.wrapped = (
      (prevX + this.vx < 0 || prevX + this.vx >= width) || 
      (prevY + this.vy < 0 || prevY + this.vy >= height)
    );
    
    // Only add to trail if we didn't wrap around
    if (!this.wrapped) {
      this.trail.push(createVector(this.x, this.y));
      
      // Limit trail length
      if (this.trail.length > this.maxTrailLength) {
        this.trail.shift();
      }
    } else {
      // Clear trail when wrapping around edges
      this.trail = [createVector(this.x, this.y)];
    }
    
    // Get 3 sensor positions based on current position and heading
    this.getSensorPos(this.rSensorPos, this.heading + this.sensorAngle);
    this.getSensorPos(this.lSensorPos, this.heading - this.sensorAngle);
    this.getSensorPos(this.fSensorPos, this.heading);
  
    // Get color values from sensor positions
    let r = this.getPixelValue(this.rSensorPos.x, this.rSensorPos.y);
    let l = this.getPixelValue(this.lSensorPos.x, this.lSensorPos.y);
    let f = this.getPixelValue(this.fSensorPos.x, this.fSensorPos.y);
    
    // Compare values to determine movement 
    if (f > l && f > r) {
      this.heading += 0;
    } else if (f < l && f < r) {
      if (random(1) < 0.5) {
        this.heading += this.rotAngle;
      } else {
        this.heading -= this.rotAngle;
      }
    } else if (l > r) {
      this.heading -= this.rotAngle;
    } else if (r > l) {
      this.heading += this.rotAngle;
    }
    
    // Small random heading changes for more organic movement
    this.heading += random(-5, 5);
    
    // Random chance to branch out
    if (random(1) < this.branchChance) {
      this.shouldBranch = true;
    }
  }
  
  getPixelValue(x, y) {
    x = constrain(floor(x), 0, width-1);
    y = constrain(floor(y), 0, height-1);
    
    if (pixels) {
      let d = pixelDensity();
      let index = 4 * ((y * width) + x) * d;
      
      if (index >= 0 && index < pixels.length) {
        return pixels[index];
      }
    }
    return 0;
  }
  
  display() {
    // Only draw lines, no dots
    if (this.trail.length >= 2) {
      stroke(this.trailColor);
      strokeWeight(this.r);
      noFill();
      
      beginShape();
      for (let i = 0; i < this.trail.length; i++) {
        // Skip points that are too close to each other
        if (i > 0) {
          let d = dist(this.trail[i-1].x, this.trail[i-1].y, this.trail[i].x, this.trail[i].y);
          if (d > width/2) continue; // Skip if distance is too large (wrap-around artifact)
        }
        vertex(this.trail[i].x, this.trail[i].y);
      }
      endShape();
    }
  }
  
  getSensorPos(sensor, angle) {
    sensor.x = (this.x + this.sensorDist*cos(angle) + width) % width;
    sensor.y = (this.y + this.sensorDist*sin(angle) + height) % height;
  }
  
  branch() {
    if (!this.shouldBranch) return null;
    
    // Reset branch flag
    this.shouldBranch = false;
    
    // Create a new mold at current position but with a different direction
    let newMold = new Mold();
    newMold.x = this.x;
    newMold.y = this.y;
    newMold.heading = this.heading + random(-90, 90);
    
    // Start with a single point in the trail
    newMold.trail = [createVector(this.x, this.y)];
    
    // Slightly vary the color
    newMold.trailColor = color(
      red(this.trailColor) + random(-20, 20),
      green(this.trailColor) + random(-20, 20),
      blue(this.trailColor) + random(-20, 20),
      alpha(this.trailColor)
    );
    
    return newMold;
  }
}

let molds = [];
let num = 700; // Reduced number of initial molds
let debugMode = false;

function setup() {
  let canvas = createCanvas(windowWidth, windowHeight);
  canvas.parent("canvas-container");
  angleMode(DEGREES);
  
  // Initialize with a black background
  background(0);
  
  // Create molds spread throughout the canvas
  for (let i = 0; i < num; i++) {
    molds.push(new Mold());
  }
}

function draw() {
  // Semi-transparent background for fading effect
  fill(0, 5);
  noStroke();
  rect(0, 0, width, height);
  
  // Load pixels for analysis
  loadPixels();
  
  // Update and display molds
  for (let i = 0; i < molds.length; i++) {
    molds[i].update();
    molds[i].display();
    
    // Check if mold should branch
    let newMold = molds[i].branch();
    if (newMold && molds.length < 1800) { // Limit total number of molds
      molds.push(newMold);
    }
  }
  
  // Limit framerate for slower animation
  frameRate(30);
}

function windowResized() {
  resizeCanvas(windowWidth, windowHeight);
  background(0);
}
