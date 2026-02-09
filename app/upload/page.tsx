'use client';

import { Suspense } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { FileUpload } from '@/components/upload/file-upload';
import { ProfilePictureUpload } from '@/components/upload/profile-picture-upload';
import { Badge } from '@/components/ui/badge';
import { Upload, Image, FileText, Mail } from 'lucide-react';
import { ImageUploader } from '@/components/upload/image-uploader';

export default function UploadTestPage() {
    const handleFileUpload = (result: any) => {
        console.log('File uploaded:', result);
    };

    const handleFilesUpload = (files: any[]) => {
        console.log('Files uploaded:', files);
    };

    const handleFileError = (error: string) => {
        console.error('Upload error:', error);
    };

    return (
        <div className="container mx-auto py-8 px-4 max-w-6xl">
            <div className="mb-8">
                <h1 className="text-3xl font-bold mb-2 flex items-center gap-2">
                    <Upload className="h-8 w-8" />
                    S3 File Upload Testing Page
                </h1>
                <p className="text-muted-foreground">
                    Test all file upload components with AWS S3 integration
                </p>
            </div>

            <Tabs defaultValue="profile" className="space-y-6">
                <TabsList className="grid w-full grid-cols-3">
                    <TabsTrigger value="profile" className="flex items-center gap-2">
                        <Image className="h-4 w-4" />
                        Profile Pictures
                    </TabsTrigger>
                    <TabsTrigger value="documents" className="flex items-center gap-2">
                        <FileText className="h-4 w-4" />
                        Documents
                    </TabsTrigger>
                    <TabsTrigger value="attachments" className="flex items-center gap-2">
                        <Mail className="h-4 w-4" />
                        Email Attachments
                    </TabsTrigger>
                </TabsList>

                <TabsContent value="profile" className="space-y-6">
                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <Image className="h-5 w-5" />
                                Profile Picture Upload
                            </CardTitle>
                            <CardDescription>
                                Test profile picture uploads with image validation and preview
                            </CardDescription>
                            <div className="flex gap-2">
                                <Badge variant="secondary">Max: 1MB</Badge>
                                <Badge variant="secondary">Types: JPG, PNG, GIF, WebP</Badge>
                                <Badge variant="secondary">Bucket: profile-pictures</Badge>
                            </div>
                        </CardHeader>
                        <CardContent>
                            <Suspense fallback={<div>Loading profile upload component...</div>}>
                                <ProfilePictureUpload
                                    currentImageUrl=""
                                    onImageUploaded={handleFileUpload}
                                />
                            </Suspense>
                        </CardContent>
                    </Card>
                </TabsContent>

                <TabsContent value="documents" className="space-y-6">
                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <FileText className="h-5 w-5" />
                                Document Upload
                            </CardTitle>
                            <CardDescription>
                                Test document uploads with comprehensive file type support
                            </CardDescription>
                            <div className="flex gap-2 flex-wrap">
                                <Badge variant="secondary">Max: 25MB</Badge>
                                <Badge variant="secondary">PDF, DOC, DOCX</Badge>
                                <Badge variant="secondary">XLS, XLSX, PPT, PPTX</Badge>
                                <Badge variant="secondary">TXT, CSV, Images</Badge>
                                <Badge variant="secondary">Bucket: documents</Badge>
                            </div>
                        </CardHeader>
                        <CardContent>
                            <Suspense fallback={<div>Loading document upload component...</div>}>
                                <FileUpload
                                    fileType="DOCUMENTS"
                                    multiple={true}
                                    onFilesUploaded={handleFilesUpload}
                                    onError={handleFileError}
                                    className="min-h-[200px]"
                                />
                            </Suspense>
                        </CardContent>
                    </Card>
                </TabsContent>

                <TabsContent value="attachments" className="space-y-6">
                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <Mail className="h-5 w-5" />
                                Email Attachment Upload
                            </CardTitle>
                            <CardDescription>
                                Test email attachment uploads with broad file type support
                            </CardDescription>
                            <div className="flex gap-2 flex-wrap">
                                <Badge variant="secondary">Max: 25MB</Badge>
                                <Badge variant="secondary">Most file types supported</Badge>
                                <Badge variant="secondary">Bucket: email-attachments</Badge>
                            </div>
                        </CardHeader>
                        <CardContent>
                            <Suspense fallback={<div>Loading attachment upload component...</div>}>
                                <FileUpload
                                    fileType="EMAIL_ATTACHMENTS"
                                    multiple={true}
                                    onFilesUploaded={handleFilesUpload}
                                    onError={handleFileError}
                                    className="min-h-[200px]"
                                />
                            </Suspense>
                        </CardContent>
                    </Card>
                </TabsContent>
            </Tabs>

            <Separator className="my-8" />

            <Card>
                <CardHeader>
                    <CardTitle>Upload Test Results</CardTitle>
                    <CardDescription>
                        Check the browser console for detailed upload results and errors
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="space-y-2 text-sm">
                        <p><strong>Success:</strong> File upload results will be logged to console</p>
                        <p><strong>Errors:</strong> Upload errors will be logged to console</p>
                        <p><strong>Network:</strong> Check Network tab to see API calls to /api/files</p>
                        <p><strong>S3:</strong> Successful uploads will appear in the configured S3 buckets</p>
                    </div>
                </CardContent>
            </Card>

            <Card className="mt-6">
                <CardHeader>
                    <CardTitle>Testing Instructions</CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="space-y-4 text-sm">
                        <div>
                            <h4 className="font-semibold mb-2">Before Testing:</h4>
                            <ul className="list-disc list-inside space-y-1">
                                <li>Ensure AWS credentials are configured</li>
                                <li>Verify S3 buckets exist: profile-pictures, documents, email-attachments</li>
                                <li>Check that CORS is configured on your S3 buckets</li>
                                <li>Open browser console to see upload results</li>
                            </ul>
                        </div>
                        <div>
                            <h4 className="font-semibold mb-2">Test Cases to Try:</h4>
                            <ul className="list-disc list-inside space-y-1">
                                <li>Upload files within size limits</li>
                                <li>Try uploading files that exceed size limits</li>
                                <li>Test with unsupported file types</li>
                                <li>Test drag and drop functionality</li>
                                <li>Test multiple file uploads (where supported)</li>
                                <li>Test upload cancellation</li>
                            </ul>
                        </div>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}