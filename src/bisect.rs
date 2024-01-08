#[derive(Debug)]
pub struct Bisect {
    min: u64,
    max: u64,
}

impl Bisect {
    pub fn new(min: u64, max: u64) -> Self {
        Self { min, max }
    }

    pub fn next(&self) -> Option<u64> {
        if self.min == self.max {
            None
        } else {
            Some(self.with())
        }
    }

    pub fn reject(&mut self) {
        self.max = self.with().saturating_sub(1);
    }

    pub fn accept(&mut self) {
        self.min = self.with();
    }

    fn with(&self) -> u64 {
        if self.max - self.min > 1 {
            u64::try_from((self.min as u128 + self.max as u128) / 2).unwrap()
        } else {
            self.max
        }
    }

    pub fn finish(&self) -> Result<u64, ()> {
        if self.min == self.max {
            Ok(self.min)
        } else {
            Err(())
        }
    }

    // ----- Getter & Setter

    pub fn min(&self) -> u64 {
        self.min
    }

    pub fn max(&self) -> u64 {
        self.max
    }
}

#[cfg(test)]
mod tests {
    use crate::bisect::Bisect;

    #[test]
    fn test_api() {
        for expected_maximum in 0..=100 {
            println!("Expected {}", expected_maximum);

            let mut bisect = Bisect::new(0, u64::MAX);

            loop {
                println!("BEFORE {:?}", bisect);

                if let Some(current) = bisect.next() {
                    println!("current {}", current);

                    // Our test.
                    if current <= expected_maximum {
                        println!("accept");
                        bisect.accept();
                    } else {
                        println!("reject");
                        bisect.reject();
                    }
                } else {
                    break;
                }

                println!("AFTER {:?}", bisect);
            }

            let got = bisect.finish().unwrap();

            println!("Got {got}");
            assert_eq!(expected_maximum, got);
        }
    }
}
