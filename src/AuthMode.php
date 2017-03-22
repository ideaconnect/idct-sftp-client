<?php
namespace IDCT\Networking\Ssh;

use \Exception as Exception;

/**
 * AuthMode for SftpClient
 *
 * @package SftpClient
 * @version 1.0
 *
 * @copyright Bartosz Pachołek
 * @copyleft Bartosz pachołek
 * @author Bartosz Pachołek
 * @license http://opensource.org/licenses/MIT (The MIT License)
 *
 * Copyright (c) 2014, IDCT IdeaConnect Bartosz Pachołek (http://www.idct.pl/)
 * Copyleft (c) 2014, IDCT IdeaConnect Bartosz Pachołek (http://www.idct.pl/)
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
 * OR OTHER DEALINGS IN THE SOFTWARE.
 */
class AuthMode
{
    const NONE = 0;
    const PASSWORD = 1;
    const PUBLIC_KEY = 2;
    const BOTH = 3;
}
