require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

async function testUpload() {
  console.log("Testing upload to 'media' bucket...");
  const dummyBuffer = Buffer.from('hello world');
  const { data, error } = await supabase.storage.from('media').upload('test.txt', dummyBuffer, {
    contentType: 'text/plain',
    upsert: true
  });

  if (error) {
    console.error("Upload Error:", error);
  } else {
    console.log("Upload Success:", data);
  }
}

testUpload();
